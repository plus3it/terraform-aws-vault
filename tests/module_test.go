package testing

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/hashicorp/vault/api"
)

func TestModule(t *testing.T) {
	files, err := ioutil.ReadDir("./")
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		// look for directories with test cases in it
		if f.IsDir() {
			if f.Name() != "vendor" {
				testFiles, testErr := ioutil.ReadDir(f.Name())
				if testErr != nil {
					log.Fatal(testErr)
				}

				// see if a prereq directory exists
				for _, testF := range testFiles {
					if testF.IsDir() {
						if testF.Name() == "prereq" {
							directory := f.Name() + "/" + testF.Name()
							runTerraformPreReq(t, directory)
						}
					}
				}

				// run terraform code
				runTerraform(t, f.Name())
			}
		}
	}
}

// The prequisite function runs the terraform code but doesn't destroy it afterwards so that the state can be used for further testing
func runTerraformPreReq(t *testing.T, directory string) {
	terraformOptions := &terraform.Options{
		TerraformDir: directory,
		NoColor:      true,
	}

	// This will run `terraform init` and `terraform apply` and fail the test if there are any errors
	terraform.InitAndApply(t, terraformOptions)
}

func runTerraform(t *testing.T, directory string) {
	terraformOptions := &terraform.Options{
		// The path to where your Terraform code is located
		TerraformDir: directory,
		// Disable color output
		NoColor: true,
	}

	// At the end of the test, run `terraform destroy` to clean up any resources that were created
	defer terraform.Destroy(t, terraformOptions)

	// This will run `terraform init` and `terraform apply` and fail the test if there are any errors
	terraform.InitAndApply(t, terraformOptions)

	testVaultViaAlb(t, terraformOptions)
}

// Use the Vault client to connect to the Vault via the ALB, via the route53 record, and make sure it works without
// Vault or TLS errors
func testVaultViaAlb(t *testing.T, terraformOptions *terraform.Options) {
	clusterURL := terraform.Output(t, terraformOptions, "cluster_url")
	description := fmt.Sprintf("Testing Vault via ALB at cluster URL %s", clusterURL)
	logger.Logf(t, description)

	maxRetries := 30
	sleepBetweenRetries := 10 * time.Second

	vaultClient := createVaultClient(t, clusterURL)

	out := retry.DoWithRetry(t, description, maxRetries, sleepBetweenRetries, func() (string, error) {
		isInitialized, err := vaultClient.Sys().InitStatus()
		if err != nil {
			return "", err
		}
		if isInitialized {
			return "Successfully verified that Vault cluster is initialized.!", nil
		} else {
			return "", errors.New("Expected Vault cluster to be initialized, but ALB reports it is not.")
		}
	})

	logger.Logf(t, out)
}

// Create a Vault client configured to talk to Vault running at the given domain name
func createVaultClient(t *testing.T, clusterURL string) *api.Client {
	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("%s", clusterURL)

	// The TLS cert we are using in this test does not have the ELB DNS name in it, so disable the TLS check
	clientTLSConfig := config.HttpClient.Transport.(*http.Transport).TLSClientConfig
	clientTLSConfig.InsecureSkipVerify = true

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create Vault client: %v", err)
	}

	return client
}

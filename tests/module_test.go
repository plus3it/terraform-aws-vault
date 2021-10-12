package testing

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
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
		if f.IsDir() && f.Name() != "vendor" {
			t.Run(f.Name(), func(t *testing.T) {
				// check if a prereq directory exists
				prereqDir := f.Name() + "/prereq/"
				if _, err := os.Stat(prereqDir); err == nil {
					prereqOptions := createTerraformOptions(prereqDir)
					defer terraform.Destroy(t, prereqOptions)
					terraform.InitAndApply(t, prereqOptions)
				}

				// run terraform code for test case
				terraformOptions := createTerraformOptions(f.Name())
				defer terraform.Destroy(t, terraformOptions)
				terraform.InitAndApply(t, terraformOptions)
				testVaultViaAlb(t, terraformOptions)
			})
		}
	}
}

func createTerraformOptions(directory string) *terraform.Options {
	terraformOptions := &terraform.Options{
		TerraformDir: directory,
		NoColor:      true,
	}

	return terraformOptions
}

// Use the Vault client to connect to the Vault via the ALB, via the route53 record, and make sure it works without
// Vault or TLS errors
func testVaultViaAlb(t *testing.T, terraformOptions *terraform.Options) {
	clusterURL := terraform.Output(t, terraformOptions, "cluster_url")
	description := fmt.Sprintf("Testing Vault via ALB at cluster URL %s", clusterURL)
	logger.Logf(t, description)

	maxRetries := 3
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

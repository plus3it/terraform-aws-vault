package testing

import (
	"io/ioutil"
	"log"
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
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
}

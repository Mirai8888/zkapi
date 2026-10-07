package zkapi

import (
	"os"
	"testing"
)

// The packaged deployments are not_deployed placeholders until the
// concession-exit vault is deployed. Package tests run against invented,
// deployed concession profiles instead; tests of the packaged placeholders
// read deploymentFiles directly.
func TestMain(m *testing.M) {
	restore := SetPackagedDeploymentsForTesting(os.DirFS("testdata/deployed"))
	code := m.Run()
	restore()
	os.Exit(code)
}

# The provider configuration CI uses to parse the committed Azure sample artifacts.
#
# A second file rather than a second block in provider-check.tf, and that is not
# symmetry for its own sake: `tofu init` downloads every provider a workspace
# declares, so one combined file would pull the AWS provider into each Azure
# workspace and the azurerm provider into each AWS one -- roughly doubling the
# download for artifacts that name resources from one cloud only. Splitting also lets
# each cloud's plugin-cache key be keyed on the file that actually declares its
# constraint.
#
# Shape differs from the AWS file in three ways, each of which is a real azurerm
# requirement rather than a stylistic choice:
#
#   * no `region`. An azurerm provider block has no such argument; writing one by
#     analogy to the AWS file fails to load. Location is per-resource in Azure, which
#     is also why the generated `.tf` files are not split per location.
#   * `subscription_id` is required from azurerm 4.0 onward. Omitting it is an error
#     rather than a default. The value below is the all-zeros placeholder: nothing in
#     this job authenticates or reaches Azure -- `init -backend=false` plus `validate`
#     read the schema and never call ARM -- so a real subscription id here would be
#     both useless and a detail about someone's tenant committed to a public repo.
#   * `features {}`. Present in every published example. Measured against the real
#     schema: it carries no `min_items`, and a provider block without it validates on
#     5.0.1, 4.81.0 and 3.117.1. Kept because omitting it would look like an
#     oversight to every reader who has seen the documented form.
#
# `~> 5.0` here, where the AWS file uses `>= 5.0`. The AWS spread across two majors is
# deliberate extra coverage justified by two confirmed schema facts; no equivalent
# measurement has been made for azurerm 6.x, which does not exist yet. Pinning the
# major means this check reports a real drift signal when azurerm 6 lands rather than
# failing on the day it is published for reasons nobody has looked into. The drift
# canary is where an unpinned upgrade belongs, and it has an azurerm schema step of
# its own for exactly that.
#
# Not committed under examples/sample-output-azure/, because the generator does not
# produce it; the artifacts are meant to be dropped into a workspace that already has
# a provider configured.
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "00000000-0000-0000-0000-000000000000"
}

# The provider configuration CI uses to parse the committed sample artifacts.
#
# A standalone file rather than a heredoc inside ci.yml, for two reasons. It is the
# one place the provider version constraint for that check is declared, so the plugin
# cache can be keyed on this file's hash -- keyed on ci.yml instead, every unrelated
# workflow edit would miss the cache and re-download 147 MB. And it makes the
# constraint reviewable on its own, which matters because raising it changes which
# provider major the shipped sample is validated against.
#
# `>= 5.0` resolves to the newest release, currently 6.58.0. The test suite validates
# against `~> 5.0` (tests/conftest.py), so the two check different majors. That is
# left as-is deliberately: both were confirmed to agree on the schema facts this tool
# depends on -- `aws_dynamodb_table` validates with no `hash_key`, and
# `aws_db_instance` still requires `instance_class` -- so the spread is coverage
# rather than an inconsistency to collapse.
#
# Not committed as part of examples/sample-output/, because it is not something the
# generator produces; the artifacts are meant to be dropped into a workspace that
# already has a provider configured.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

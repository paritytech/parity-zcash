workflow "On Push" {
  on = "push"
  resolves = ["Doc", "Build Fuzz Targets"]
}

action "Build" {
  uses = "./.github"
  args = "cargo build --release"
}

action "Test" {
  needs = "Build"
  uses = "./.github"
  args = "cargo test --all"
}

# Filter for master branch
action "if branch = master:" {
  needs = "Test"
  uses = "actions/bin/filter@master"
  args = "branch master"
}

action "Doc" {
  needs = "if branch = master:"
  uses = "./.github/"
  args = "cargo doc"
}

# Filter for fuzz branch
# TODO: remove when fuzzing merged to master
action "if branch = fuzz:" {
  needs = "Test"
  uses = "actions/bin/filter@master"
  args = "branch fuzz"
}

action "Build Fuzz Targets" {
  needs = "if branch = fuzz:"
  uses = "./.github/"
  args = "cargo afl build"
}

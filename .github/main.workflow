workflow "On Push" {
  on = "push"
  resolves = ["Doc", "Build Fuzz Targets"]
}

action "Test" {
  uses = "./.github"
  args = "cargo test --all"
}

action "Build" {
  needs = "Test"
  uses = "./.github"
  args = "cargo build --release"
}

# Filter for master branch
action "if branch = master:" {
  needs = "Build"
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
  needs = "Build"
  uses = "actions/bin/filter@master"
  args = "branch fuzz"
}

action "Build Fuzz Targets" {
  needs = "if branch = fuzz:"
  uses = "./.github/"
  args = "cargo afl build"
}

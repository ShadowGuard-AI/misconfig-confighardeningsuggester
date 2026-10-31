![Banner](banner.png)

# misconfig-ConfigHardeningSuggester
Analyzes configuration files and suggests security hardening measures based on industry best practices and known vulnerabilities, providing specific, actionable recommendations and commands. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-confighardeningsuggester`

Running this tool creates no files. A starter rules.json ships in the repo, and --rules names a different one; the rules are loaded once, from the file named, and a run with --rules does not depend on the default file at all. A rules file holding no rules ends the run at exit 1, because nothing was checked.

If yamllint or jsonlint is not installed, the lint step is skipped with a note and the rule checks still run. Parse failures and unsupported file types are reported as errors at exit 1, never as suggestions. A config that does not hold a mapping (an empty file, a scalar document) is reported as not analyzed at exit 1.

## Usage
`./misconfig-confighardeningsuggester [params]`

## Parameters
- `-h`: Show help message and exit
- `--rules`: Path to the hardening rules JSON file. Defaults to rules.json

## License
Copyright (c) ShadowStrikeHQ

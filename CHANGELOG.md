# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Support for multiple defined forwards in the SSH config file [#185]
- Dynamic port forwarding, through the new `start dynamic` and `add alias
  dynamic` commands, which turn a source endpoint into a SOCKS5 proxy reaching
  every address its clients ask for from the ssh server. Host names are resolved
  by the ssh server, so names that only exist in the remote network can be used,
  and `DynamicForward` is read from the SSH config file when no `--source` is
  given. Only the `CONNECT` command is served, since a ssh tunnel carries tcp
  alone

### Fixed
- Detached instances no longer lose the last two command line arguments. The id
  argument was written over them instead of after them, so `start alias <name>
  --detach` reached the child process without the alias name and
  `start local --server <host> --detach` without the server
- `start alias` accepts the hidden `--id` flag, without which a detached
  instance failed to start [#184]
- An alias with no `ssh-config` set no longer overrides the value given through
  the `--config` flag [#192]
- Close the SSH config file after reading it [#198]
- Bump `tzinfo`, `activesupport` and `nokogiri` used to build the documentation
  site [#190] [#194] [#196]
- A stale pid file no longer blocks `start` for good. The check for another
  instance using the same id treated any pid that still resolved as a running
  instance: on windows a process object, and with it the pid, outlives the
  process for as long as anything still holds a handle to it, and on linux a
  process that has exited but has not been reaped by its parent keeps its entry
  in the process table

### Changed
- CI runs the build and the test suite on windows as well as linux
- Bump all dependencies to their latest versions, which raises the minimum Go version to 1.25
- Replace the archived `github.com/mitchellh/mapstructure` with the maintained `github.com/go-viper/mapstructure/v2`
- Replace the archived `github.com/mitchellh/go-ps` with the standard library
- Replace the deprecated `golang.org/x/crypto/ssh/terminal` with `golang.org/x/term`
- `show` now fails with "unknown command" instead of silently exiting 0 when given
  a subcommand it does not have

### Deleted
- Remove the `show logs` command. A detached instance writes its log to
  `$HOME/.mole/<instance-id>/mole.log`, which can be read with any tool;
  `tail -f` replaces `mole show logs --follow`

## [2.0.0] - 2021-09-28
### Added
- Add [CHANGELOG.md](https://github.com/davrodpin/mole/blob/master/CHANGELOG.md) file to track changes on releases [89290e8]
- Add new command to show running configuration of any mole instance [#161]
- Stop foreground instances using the `stop` command [#158]
- Add new command, `misc rpc` to explicitly execute procedures on running instances of mole [#148]
- rpc server (disabled by default) [#146]
- New flag to pass SSH config file path [#136]
- Add new command: show logs  [#132]

### Changed
- Change output of "show alias" to toml format. [#144]
- Skip private key authentication in case of error (encrypted without passphrase, wrong format, ...) [#159] [#169]
- Close reader/writer on ssh channel when finished or error occurs [#159]
- Don't fail but create new empty config when no config (empty string) file was used [#159]
- Fix start alias flag parsing [#157]

### Deleted

## [1.0.1] - 2020-09-01
### Added
- The installation script can now receive a parameter to install a specific version instead of always installing the latest [#124]

### Changed
- Verbose, Insecure and Detach flags working when loading from an alias [#127]

### Deleted

## [1.0.0] - 2020-08-13
### Added
- Support for ssh remote port forwarding [#114]
- Support for authentication ssh session using ssh agent [#102]
- Add builds for ARM [#109]

### Changed
- Complete revamp of CLI user experience [#112]

### Deleted

## [0.5.0] - 2019-10-02
### Added
- Configurable connection timeout [#92]
- Keep idle connection open by sending periodic synthetic packets (-keep-alive-interval flag) [#77]

### Changed
- Reconnect to SSH Server if connection drops for any reason (-connection-retries and -retry-wait) [#95]
- SSH config file is required even if all required arguments were provided through CLI [#75]
- Missing port in remote address [#86]
- Fix persistence of insecure mode flag (-insecure) [#90]
- Better protecting keys loaded in memory [#78]

### Deleted

## [0.4.0] - 2019-06-23
### Added
- Multiple tunnels using the same ssh connection (support for multiple -remote flags) [#72]

### Changed
- Project dependencies are now managed by Go modules instead of vendor/ [#69]

### Deleted

## [0.3.0] - 05-11-2019
### Added
- Windows Support! Mole now works on windows (tested on Windows 10) [#65]
- Using Github Actions for code quality checks (e.g. unit tests, code formatting, etc.)
- Skip the host key validation by using the -insecure option [#52]
- Always use the same ssh connection if multiple clients use the same tunnel [#43]
- Run mole in background by using the -detach option [#35]
- New -aliases option added to list all configured aliases [#29]
- LocalForward option from ssh config file will be used if both -local and -remote are absent [#18]
- Developers can spawn a small local infra using docker to test their changes

### Changed
- Users will be prompted to enter the key's password if it is encrypted [#54]
- Server names can contain underscore character [#50]
- Return error if required flags are missing [#33]

### Deleted

## [0.2.0] - 2018-10-14
### Added
- Aliases can be created to reuse tunnel settings.

### Changed

### Deleted

## [0.1.0] - 2018-10-10
### Added
- Add -version option to display the current version
- New website: https://davrodpin.github.io/mole/

### Changed
- IP addresses of both local and remote are now optional

### Deleted

## [0.0.1] - 2018-10-05
### Added
- First release. No changes.

### Changed

### Deleted


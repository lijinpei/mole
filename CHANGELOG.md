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
- Reverse dynamic port forwarding, through the new `start reverse-dynamic` and
  `add alias reverse-dynamic` commands, which ask the ssh server to listen on a
  source endpoint and serve a SOCKS5 proxy on it, reaching every address its
  clients ask for from the machine running mole. Host names are resolved there
  as well, since they name what only that side can reach, and a `RemoteForward`
  carrying a source endpoint alone is read from the SSH config file when no
  `--source` is given, the same way `ssh -R 1080` asks for one
- `--socks-auth <user>:<password>` makes the SOCKS5 proxy of a dynamic or a
  reverse dynamic tunnel ask its clients to authenticate, which matters most for
  a reverse dynamic one: its endpoint is served by the ssh server, so whoever
  reaches that server reaches the proxy. A value starting with `$` names the
  environment variable carrying the credentials, so the password is neither
  given on the command line nor kept in the alias file, and it is left out of
  what an instance reports about itself

### Fixed
- A tunnel that cannot listen on the endpoints it asks the ssh server for no
  longer gives up for good. The connection retries were only spent on reaching
  the server, so a tunnel reconnecting to a server that had not released the
  endpoint of the connection that just died stopped instead of asking for it
  again a moment later. An endpoint on the machine mole runs on is still taken
  for good, since asking again does not take it from whoever holds it
- The connection to the ssh server is now established by a single goroutine from
  the first connection to the last. A connection lost while another one was
  being established had a second one start alongside it, leaving the tunnel with
  a connection and a set of listeners nothing was watching, and a tunnel stopped
  while connecting could leave both behind after `Start` had already returned
- The address a socks proxy reached an endpoint from is no longer reported back
  to the client that asked for it. A reverse dynamic tunnel reaches addresses
  from the machine it runs on, so its clients, which are on the other side of
  the ssh server, were told about that machine's network one address at a time
- A socks proxy no longer waits for a connection that never answers for as long
  as the operating system takes to give up, which is a couple of minutes: a
  client asking for addresses that swallow what is sent to them held everything
  serving it for that long at no cost to itself
- A tunnel listening on the ssh server no longer turns a source address naming a
  host into `0.0.0.0`. The endpoint was taken from the listener, which reports
  the address it could parse rather than the one it asked for, so a `--source
  localhost:8080` was reported as `0.0.0.0:8080` and every reconnection asked
  the server to listen on every interface instead of on the address it was told
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
- A connection forwarded by a local or remote tunnel is no longer torn down as
  soon as one of its two directions is done. A client that stopped sending, by
  half closing its side of the connection, had the answer still on its way cut
  short, and every connection that ended logged, at error level, the failure the
  direction that lost the race got from the socket the other one had just closed.
  Each direction now tells the end it writes to that nothing else is coming,
  leaving the opposite one free to carry on, and both ends are released together
  once the two directions are done, the connection to the ssh server carrying
  them is gone, or the tunnel stops

### Changed
- CI runs the build and the test suite on windows as well as linux
- The ssh server used by the test suite serves the endpoints it is asked to
  forward instead of replying with a port it never listens on, which is what a
  remote or a reverse dynamic tunnel needs to be reached at all. The
  `github.com/phayes/freeport` dependency went with the port it was picking
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


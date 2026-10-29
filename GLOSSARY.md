# Mole

Mole forwards TCP connections through SSH, with named configurations and resilient connections.

## Language

**Alias**:
A named, saved configuration for an Instance containing one or more Tunnels.
_Avoid_: Tunnel when referring to the whole Alias

**Instance**:
One running copy of Mole, identified by a single name or id, whose Tunnels are started and stopped together.
_Avoid_: Tunnel when referring to the whole Instance

**Tunnel**:
A resilient connection to one SSH server carrying one or more Forwards.

**Forward**:
A group of source endpoints of one forwarding kind carried by a Tunnel. Local and remote Forwards have fixed destinations; dynamic and reverse-dynamic Forwards have destinations chosen by each connecting client.

**SSH channel**:
In Mole, one source endpoint of a Forward, with a fixed or client-selected destination.

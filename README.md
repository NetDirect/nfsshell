nfsshell
========

> [!NOTE]
> Fork of [NetDirect/nfsshell](https://github.com/NetDirect/nfsshell) that has been updated to use libtirpc because librpc has been deprecated.

> [!TIP]
> Compiles and works on Kali Linux 2024.3. Make sure to install `libtirpc-dev` and `libreadline-dev` from the kali repositories.

NFS shell that provides user level access to an NFS server, over UDP or TCP,
supports source routing and "secure" (privileged port) mounts. It's a
useful tool to manually check (or show) security problems after a security
scanner has detected them.

Originally released by Leendert van Doorn, updated to support NFSv3 by Michael Brown

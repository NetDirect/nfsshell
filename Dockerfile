FROM ubuntu:xenial-20161114 as build
RUN DEBIAN_FRONTEND=noninteractive apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install make gcc libtirpc-dev libncurses-dev libreadline-dev -y
COPY ./ /nfsshell
WORKDIR /nfsshell
RUN make

FROM ubuntu:xenial-20161114
COPY --from=build /nfsshell/nfsshell /bin/nfsshell
ENTRYPOINT ["/bin/nfsshell"]
# Docker User Namespace Enforcement Plugin

This project is a very basic [Docker AuthZ plugin][1] that blocks the ability
to use `--userns=host` when a container is created (ie: via API, or through
`docker create` or `docker run`).

## Why?

Docker supports [user namespaces][2], allowing containers to have their users
re-mapped to a specific UID/GID range outside of the container. However,
in a scenario where sibling containers are desired, it's easily plausible that a
jailbreak can be done by simply running `--userns=host`, and mapping whatever
you wanted to achieve the classic scenario that one has probably seen mentioned
a thousand times.

Unfortunately, by default, there is no way to restrict this behaviour in the
Docker daemon. It's the job of authorization plugins to enforce any restrictions
that may be necessary.

Hence this is a very short and sweet plugin that does that any only that. It
watches [`/containers/create`][3] for requests with `HostConfig: { "UsernsMode":
"host" }` and blocks them. Some basic audit logging is also done so that
attempts to launch into the host namespace are logged.

## Installation and Usage

Clone the repo, and run within the project:

```
go build -o denyusernshost
```

Copy the `denyusernshost` binary to a place of your choice, ie:
`/usr/local/sbin`. Use the service manager of your choice to manage the service.
You can also use [systemd socket activation][4] to easily start the service on
demand.

Logs are streamed to standard error. `-debug` adds some extra debug messages
to the log.

If running in the foreground, you can press CTRL-C to stop the server. SIGTERM
also works (obviously for use when running as a service).

Once installed and running, edit your Docker daemon launch command to include
`--authorization-plugin=denyusernshost`, or add it to your
`/etc/docker/daemon.json` file. Example below:

```
{
	"authorization-plugins": ["denyusernshost"]
}
```

## License

```
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
```

[1]: https://docs.docker.com/engine/extend/plugins_authorization/
[2]: https://docs.docker.com/engine/reference/commandline/dockerd/#/daemon-user-namespace-options
[3]: https://docs.docker.com/engine/reference/api/docker_remote_api_v1.24/#/create-a-container
[4]: https://docs.docker.com/engine/extend/plugin_api/#/systemd-socket-activation

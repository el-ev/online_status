# Online Status

Someone is online if and only if at least one of their computers is online. Use this tool to indicate your online status.

## Usage

### Server
``` bash
$ online_status -s [-p <port>] [--pubkey </path/to/pubkey>]
```

### Client(s)
``` bash
$ online_status -c <server> [-p <port>] [--privkey </path/to/privkey>]
```

### Check online status
``` bash
$ curl <server>[:<port>]/status
```
If online: `ONLINE`, otherwise: `OFFLINE`

4. Baby's first DNS server
--------------------------

Haven gotten this far, we're ready to make our first attempt at writing an
actual server. In reality, DNS servers fullfil two different purposes:

 * Authoritative Server - A DNS server hosting one or more "zones". For
   instance, the authoritative servers for the zone google.com are
   ns1.google.com, ns2.google.com, ns3.google.com and ns4.google.com.
 * Caching Server - A DNS server that services DNS lookups by first checking
   its cache to see if it already knows of the record being requested, and if
   not performing a recursive lookup to figure it out. This includes the DNS
   server that is likely running on your home router as well as the DNS server
   that your ISP assigns to you through DHCP, and Google's public DNS servers
   8.8.8.8 and 8.8.4.4.

Strictly speaking, there's nothing to stop a server from doing both things, but
in pracice these two roles are typically mutually exclusive. This also explains
the significance of the flags `RD` (Recursion Desired) and `RA` (Recursion
Available) in the packet header -- a stub resolver querying a caching server
will set the `RD` flag, and since the server allows such queries it will
perform the lookup and send a reply with the `RA` flag set. This won't work for
an Authoritative Server which will only reply to queries relating to the zones
hosted, and as such will send an error response to any queries with the `RD`
flag set.

Don't take my word for it, though! Let's verify that this is the case. First
off, let's use `8.8.8.8` for looking up *yahoo.com*:

```text
# dig @8.8.8.8 yahoo.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +recurse @8.8.8.8 yahoo.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53231
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;yahoo.com.			IN	A

;; ANSWER SECTION:
yahoo.com.		1051	IN	A	98.138.253.109
yahoo.com.		1051	IN	A	98.139.183.24
yahoo.com.		1051	IN	A	206.190.36.45

;; Query time: 1 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Fri Jul 08 11:43:55 CEST 2016
;; MSG SIZE  rcvd: 86
```

This works as expected. Now let's try sending the same query to one of the
servers hosting the *google.com* zone:

```text
# dig @ns1.google.com yahoo.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +recurse @ns1.google.com yahoo.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 12034
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;yahoo.com.			IN	A

;; Query time: 10 msec
;; SERVER: 216.239.32.10#53(216.239.32.10)
;; WHEN: Fri Jul 08 11:44:07 CEST 2016
;; MSG SIZE  rcvd: 27
```

Notice how the status of the response says `REFUSED`! `dig` also warns us that
while the `RD` flag was set in the query, the server didn't set it in the
response. We can still use the same server for *google.com*, however:

```text
dig @ns1.google.com google.com                                                                                                                                                                                                                                 <<<

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +recurse @ns1.google.com google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28058
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		300	IN	A	216.58.211.142

;; Query time: 10 msec
;; SERVER: 216.239.32.10#53(216.239.32.10)
;; WHEN: Fri Jul 08 11:46:27 CEST 2016
;; MSG SIZE  rcvd: 44
```

No error this time -- however, `dig` still warns us that recursion is
unavailable. We can explicitly unset it using `+norecurse` which gets rid of
the warning:

```text
# dig +norecurse @ns1.google.com google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +norecurse @ns1.google.com google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15850
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		300	IN	A	216.58.211.142

;; Query time: 10 msec
;; SERVER: 216.239.32.10#53(216.239.32.10)
;; WHEN: Fri Jul 08 11:47:52 CEST 2016
;; MSG SIZE  rcvd: 44
```

This final query is the type of query that we'd expect to see a caching server
send as part of recursively resolving the name.

For our first foray into writing our own server, we'll do something even
simpler by implementing a server that simply forwards queries to another
caching server, i.e. a "DNS proxy server". Having already done most of the hard
work, it's a rather quick effort!

### Separating lookup into a separate function

We'll start out by doing some quick refactoring, moving our lookup code into
a separate function. This is for the most part the same code as we had in our
`main` function in the previous chapter, with the only change being that we
handle errors gracefully using `try!`.

```rust
fn lookup(qname: &str, qtype: QueryType, server: (&str, u16)) -> Result<DnsPacket> {
    let socket = try!(UdpSocket::bind(("0.0.0.0", 43210)));

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();
    try!(socket.send_to(&req_buffer.buf[0..req_buffer.pos], server));

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    DnsPacket::from_buffer(&mut res_buffer)
}
```

### Implementing our first server

Now we'll write our server code. First, we need get some things in order.

```rust
fn main() {
    // Forward queries to Google's public DNS
    let server = ("8.8.8.8", 53);

    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();
```

For now, queries are handled sequentially, so an infinite loop for servicing
requests is initiated.

```rust
    loop {
```

With a socket ready, we can go ahead and read a packet. This will block until
one is received.

```rust
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to read from UDP socket: {:?}", e);
                continue;
            }
        };
```

Here we use match to safely unwrap the `Result`. If everything's as expected,
the raw bytes are simply returned, and if not it'll abort by restarting the
loop and waiting for the next request. The `recv_from` function will write the
data into the provided buffer, and return the length of the data read as well
as the source adress. We're not interested in the length, but we need to keep
track of the source in order to send our reply later on.

Next, `DnsPacket::from_buffer` is used to parse the raw bytes into
a `DnsPacket`. It uses the same error handling idiom as the previous statement.

```rust
        let request = match DnsPacket::from_buffer(&mut req_buffer) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to parse UDP query packet: {:?}", e);
                continue;
            }
        };
```

At this stage, the response packet is created and initiated.

```rust
        let mut packet = DnsPacket::new();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;
```

Being mindful of how unreliable input data from arbitrary senders can be, we
need make sure that a question is actually present. If not, we return `FORMERR`
to indicate that the sender made something wrong.

```rust
        if request.questions.is_empty() {
            packet.header.rescode = ResultCode::FORMERR;
        }
```

Usually a question will be present, though.

```rust
        else {
            let question = &request.questions[0];
            println!("Received query: {:?}", question);
```

Since all is set up and as expected, the query can be forwarded to the target
server. There's always the possibility that the query will fail, in which case
the `SERVFAIL` response code is set to indicate as much to the client. If
rather everything goes as planned, the question and response records as copied
into our response packet.

```rust
            if let Ok(result) = lookup(&question.name, question.qtype, server) {
                packet.questions.push(question.clone());
                packet.header.rescode = result.header.rescode;

                for rec in result.answers {
                    println!("Answer: {:?}", rec);
                    packet.answers.push(rec);
                }
                for rec in result.authorities {
                    println!("Authority: {:?}", rec);
                    packet.authorities.push(rec);
                }
                for rec in result.resources {
                    println!("Resource: {:?}", rec);
                    packet.resources.push(rec);
                }
            } else {
                packet.header.rescode = ResultCode::SERVFAIL;
            }
```

The only thing remaining is to encode our response and send it off!

```rust
        let mut res_buffer = BytePacketBuffer::new();
        match packet.write(&mut res_buffer) {
            Ok(_) => {},
            Err(e) => {
                println!("Failed to encode UDP response packet: {:?}", e);
                continue;
            }
        };

        let len = res_buffer.pos();
        let data = match res_buffer.get_range(0, len) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to retrieve response buffer: {:?}", e);
                continue;
            }
        };

        match socket.send_to(data, src) {
            Ok(_) => {},
            Err(e) => {
                println!("Failed to send response buffer: {:?}", e);
                continue;
            }
        };
```

The match idiom for error handling is used again here, since we want to avoid
terminating our request loop at all cost. It's a bit verbose, and normally we'd
like to use `try!` instead. Unfortunately that's unavailable to us here, since
we're in the `main` function which doesn't return a `Result`.

```rust
    } // End of request loop
} // End of main
```

All done! Let's try it! We start our server in one terminal, and use `dig` to
perform a lookup in a second terminal.

```text
# dig @127.0.0.1 -p 2053 google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> @127.0.0.1 -p 2053 google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47200
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		68	IN	A	216.58.211.142

;; Query time: 1 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1)
;; WHEN: Fri Jul 08 12:07:44 CEST 2016
;; MSG SIZE  rcvd: 54
```

Looking at our server terminal we see:

```text
Received query: DnsQuestion { name: "google.com", qtype: A }
Answer: A { domain: "google.com", addr: 216.58.211.142, ttl: 96 }
```

In less than 800 lines of code, we've built a DNS server able to respond to
queries with several different record types!

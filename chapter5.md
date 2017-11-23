5 - Recursive Resolve
=====================

Our server is working, but being reliant on another server to actually perform
the lookup is annoying and less than useful. Now is a good time to dwelve into
the details of how a name is really resolved.

Assuming that no information is known since before, the question is first
issued to one of the Internet's 13 root servers. Why 13? Because that's how
many that fits into a 512 byte DNS packet (strictly speaking, there's room for
14, but some margin was left). You might think that 13 seems a bit on the low
side for handling all of the internet, and you'd be right -- there are 13
logical servers, but in reality many more. You can read more about it
[here](http://www.root-servers.org/). Any resolver will need to know of these
13 servers before hand. A file containing all of them, in bind format, is
available and called [named.root](https://www.internic.net/domain/named.root).
These servers all contain the same information, and to get started we can pick
one of them at random. Looking at `named.root` we see that the IP-adress of
*a.root-servers.net* is 198.41.0.4, so we'll go ahead and use that to perform
our initial query for *www.google.com*.

```text
# dig +norecurse @198.41.0.4 www.google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +norecurse @198.41.0.4 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64866
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 16

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.google.com.			IN	A

;; AUTHORITY SECTION:
com.			172800	IN	NS	e.gtld-servers.net.
com.			172800	IN	NS	b.gtld-servers.net.
com.			172800	IN	NS	j.gtld-servers.net.
com.			172800	IN	NS	m.gtld-servers.net.
com.			172800	IN	NS	i.gtld-servers.net.
com.			172800	IN	NS	f.gtld-servers.net.
com.			172800	IN	NS	a.gtld-servers.net.
com.			172800	IN	NS	g.gtld-servers.net.
com.			172800	IN	NS	h.gtld-servers.net.
com.			172800	IN	NS	l.gtld-servers.net.
com.			172800	IN	NS	k.gtld-servers.net.
com.			172800	IN	NS	c.gtld-servers.net.
com.			172800	IN	NS	d.gtld-servers.net.

;; ADDITIONAL SECTION:
e.gtld-servers.net.	172800	IN	A	192.12.94.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
m.gtld-servers.net.	172800	IN	A	192.55.83.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30

;; Query time: 24 msec
;; SERVER: 198.41.0.4#53(198.41.0.4)
;; WHEN: Fri Jul 08 14:09:20 CEST 2016
;; MSG SIZE  rcvd: 531
```

The root servers don't know about *www.google.com*, but they do know about
*com*, so our reply tells us where to go next. There are a few things to take
note of:

 * We are provided with a set of NS records, which are in the authority
   section. NS records tells us *the name* of the name server handling
   a domain.
 * The server is being helpful by passing along A records corresponding to the
   NS records, so we don't have to perform a second lookup.
 * We didn't actually perform a query for *com*, but rather *www.google.com*.
   However, the NS records all refer to *com*.

Let's pick a server from the result and move on. *192.5.6.30* for
*a.gtld-servers.net* seems as good as any.

```text
# dig +norecurse @192.5.6.30 www.google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +norecurse @192.5.6.30 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16229
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 5

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.google.com.			IN	A

;; AUTHORITY SECTION:
google.com.		172800	IN	NS	ns2.google.com.
google.com.		172800	IN	NS	ns1.google.com.
google.com.		172800	IN	NS	ns3.google.com.
google.com.		172800	IN	NS	ns4.google.com.

;; ADDITIONAL SECTION:
ns2.google.com.		172800	IN	A	216.239.34.10
ns1.google.com.		172800	IN	A	216.239.32.10
ns3.google.com.		172800	IN	A	216.239.36.10
ns4.google.com.		172800	IN	A	216.239.38.10

;; Query time: 114 msec
;; SERVER: 192.5.6.30#53(192.5.6.30)
;; WHEN: Fri Jul 08 14:13:26 CEST 2016
;; MSG SIZE  rcvd: 179
```

We're still not at *www.google.com*, but at least we have a set of servers that
handle the *google.com* domain now. Let's give it another shot by sending our
query to *216.239.32.10*.

```text
# dig +norecurse @216.239.32.10 www.google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +norecurse @216.239.32.10 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20432
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.google.com.            IN  A

;; ANSWER SECTION:
www.google.com.     300 IN  A   216.58.211.132

;; Query time: 10 msec
;; SERVER: 216.239.32.10#53(216.239.32.10)
;; WHEN: Fri Jul 08 14:15:11 CEST 2016
;; MSG SIZE  rcvd: 48
```

And here we go! The IP of *www.google.com* as we desired. Let's recap:

 * *a.root-servers.net* tells us to check *a.gtld-servers.net* which handles com
 * *a.gtld-servers.net* tells us to check *ns1.google.com* which handles google.com
 * *ns1.google.com* tells us the IP of *www.google.com*

This is rather typical, and most lookups will only ever require three steps,
even without caching. It's still possible to have name servers for subdomains,
and further ones for sub-subdomains, though. In practice, a DNS server will
maintain a cache, and most TLD's will be known since before. That means that
most queries will only ever require two lookups by the server, and commonly one
or zero.

### Extending DnsPacket for recursive lookups

Before we can get on, we'll need a few utility functions on `DnsPacket`.

```rust
impl DnsPacket {

    - snip -
```

First, it's useful to be able to pick a random A record from a packet. Since we
don't want to introduce an external dependency, and there's no method for
generating random numbers in the rust standard library, we'll just pick the
first entry for now.

```rust
    pub fn get_random_a(&self) -> Option<String> {
        if !self.answers.is_empty() {
            let idx = random::<usize>() % self.answers.len();
            let a_record = &self.answers[idx];
            if let DnsRecord::A{ ref addr, .. } = *a_record {
                return Some(addr.to_string());
            }
        }

        None
    }
```

Second, we'll use the fact that name servers often bundle the corresponding
A records when replying to an NS query to implement a function that returns
the actual IP for an NS record if possible.

```rust
    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {
```

First, we scan the list of NS records in the authorities section:

```rust
        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS { ref domain, ref host, .. } = *auth {
                if !qname.ends_with(domain) {
                    continue;
                }
```

Once we've found an NS record, we scan the resources record for a matching
A record...

```rust
                for rsrc in &self.resources {
                    if let DnsRecord::A{ ref domain, ref addr, ttl } = *rsrc {
                        if domain != host {
                            continue;
                        }

                        let rec = DnsRecord::A {
                            domain: host.clone(),
                            addr: *addr,
                            ttl: ttl
                        };
```

...and push any matches to a list.

```rust
                        new_authorities.push(rec);
                    }
                }
            }
        }
```

If there are any matches, we pick the first one. Again, we'll want to introduce
randomization later on.

```rust
        if !new_authorities.is_empty() {
            if let DnsRecord::A { addr, .. } = new_authorities[0] {
                return Some(addr.to_string());
            }
        }

        None
    } // End of get_resolved_ns
```

However, not all name servers are as well behaved. In certain cases there won't
be any A records in the additional section, and we'll have to perform *another*
lookup in the midst. For this, we introduce a method for returning the host
name of an appropriate name server.

```rust
    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {

        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS { ref domain, ref host, .. } = *auth {
                if !qname.ends_with(domain) {
                    continue;
                }

                new_authorities.push(host);
            }
        }

        if !new_authorities.is_empty() {
            let idx = random::<usize>() % new_authorities.len();
            return Some(new_authorities[idx].clone());
        }

        None
    } // End of get_unresolved_ns

} // End of DnsPacket
```

### Implementing recursive lookup

We move swiftly on to our new `recursive_lookup` function:

```rust
fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
```

For now we're always starting with *a.root-servers.net*.

```rust
    let mut ns = "198.41.0.4".to_string();
```

Since it might take an arbitrary number of steps, we enter an unbounded loop.

```rust
    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);
```

The next step is to send the query to the active server.

```rust
        let ns_copy = ns.clone();

        let server = (ns_copy.as_str(), 53);
        let response = try!(lookup(qname, qtype.clone(), server));
```

If there are entries in the answer section, and no errors, we are done!

```rust
        if !response.answers.is_empty() &&
           response.header.rescode == ResultCode::NOERROR {

            return Ok(response.clone());
        }
```

We might also get a `NXDOMAIN` reply, which is the authoritative name servers
way of telling us that the name doesn't exist.

```rust
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response.clone());
        }
```

Otherwise, we'll try to find a new nameserver based on NS and a corresponding A
record in the additional section. If this succeeds, we can switch name server
and retry the loop.

```rust
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns.clone();

            continue;
        }
```

If not, we'll have to resolve the ip of a NS record. If no NS records exist,
we'll go with what the last server told us.

```rust
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response.clone())
        };
```

Here we go down the rabbit hole by starting _another_ lookup sequence in the
midst of our current one. Hopefully, this will give us the IP of an appropriate
name server.

```rust
        let recursive_response = try!(recursive_lookup(&new_ns_name, QueryType::A));
```

Finally, we pick a random ip from the result, and restart the loop. If no such
record is available, we again return the last result we got.

```rust
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns.clone();
        } else {
            return Ok(response.clone())
        }
    }
} // End of recursive_lookup
```

### Trying out recursive lookup

The only thing remaining is to change our main function to use
`recursive_lookup`:

```rust
fn main() {

    - snip -

            println!("Received query: {:?}", question);
            if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
                packet.questions.push(question.clone());
                packet.header.rescode = result.header.rescode;

    - snip -

}
```

Let's try it!

```text
# dig @127.0.0.1 -p 2053 www.google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> @127.0.0.1 -p 2053 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41892
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.google.com.			IN	A

;; ANSWER SECTION:
www.google.com.		300	IN	A	216.58.211.132

;; Query time: 76 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1)
;; WHEN: Fri Jul 08 14:31:39 CEST 2016
;; MSG SIZE  rcvd: 62
```

Looking at our server window, we see:

```text
Received query: DnsQuestion { name: "www.google.com", qtype: A }
attempting lookup of A www.google.com with ns 198.41.0.4
attempting lookup of A www.google.com with ns 192.12.94.30
attempting lookup of A www.google.com with ns 216.239.34.10
Answer: A { domain: "www.google.com", addr: 216.58.211.132, ttl: 300 }
```

This mirrors our manual process earlier. We're really getting somewhere!

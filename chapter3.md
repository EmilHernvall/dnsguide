3. Adding more Record Types
---------------------------

Let's use our program to do a lookup for ''yahoo.com''.

```rust
let qname = "www.yahoo.com";
```

Running it yields:

```text
DnsHeader {
    id: 6666,
    recursion_desired: true,
    truncated_message: false,
    authoritative_answer: false,
    opcode: 0,
    response: true,
    rescode: NOERROR,
    checking_disabled: false,
    authed_data: false,
    z: false,
    recursion_available: true,
    questions: 1,
    answers: 3,
    authoritative_entries: 0,
    resource_entries: 0
}
DnsQuestion {
    name: "www.yahoo.com",
    qtype: A
}
UNKNOWN {
    domain: "www.yahoo.com",
    qtype: 5,
    data_len: 15,
    ttl: 259
}
A {
    domain: "fd-fp3.wg1.b.yahoo.com",
    addr: 46.228.47.115,
    ttl: 19
}
A {
    domain: "fd-fp3.wg1.b.yahoo.com",
    addr: 46.228.47.114,
    ttl: 19
}
```

That's odd -- we're getting an UNKNOWN record as well as two A records. The
UNKNOWN record, with query type 5 is a CNAME. There are quite a few DNS record
types, many of which doesn't see any use in practice. That said, let's have
a look at a few essential ones:

| ID  | Name  | Description                                              | Encoding                                         |
| --- | ----- | -------------------------------------------------------- | ------------------------------------------------ |
| 1   | A     | Alias - Mapping names to IP addresses                    | Preamble + Four bytes for IPv4 adress            |
| 2   | NS    | Name Server - The DNS server address for a domain        | Preamble + Label Sequence                        |
| 5   | CNAME | Canonical Name - Maps names to names                     | Preamble + Label Sequence                        |
| 15  | MX    | Mail eXchange - The host of the mail server for a domain | Preamble + 2-bytes for priority + Label Sequence |
| 28  | AAAA  | IPv6 alias                                               | Premable + Sixteen bytes for IPv6 adress         |

### Extending QueryType with more record types

Let's go ahead and add them to our code! First we'll update our `QueryType`
enum:

```rust
#[derive(PartialEq,Eq,Debug,Clone,Hash,Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
    NS, // 2
    CNAME, // 5
    MX, // 15
    AAAA, // 28
}
```

We'll also need to change our utility functions.

```rust
impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num)
        }
    }
}
```

### Extending DnsRecord for reading new record types

Now we need a way of holding the data for these records, so we'll make some
modifications to `DnsRecord`.

```rust
#[derive(Debug,Clone,PartialEq,Eq,Hash,PartialOrd,Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32
    }, // 28
}
```

Here comes the bulk of the work. We'll need to extend the functions for writing
and reading records. Starting with read, we amend it with additional code for
each record type. First off, we've got the common preamble:

```rust
pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
    let mut domain = String::new();
    try!(buffer.read_qname(&mut domain));

    let qtype_num = try!(buffer.read_u16());
    let qtype = QueryType::from_num(qtype_num);
    let _ = try!(buffer.read_u16());
    let ttl = try!(buffer.read_u32());
    let data_len = try!(buffer.read_u16());
```

After which we handle each record type separately, starting with the A record
type which remains the same as before.

```rust
    match qtype {
        QueryType::A  => {
            let raw_addr = try!(buffer.read_u32());
            let addr = Ipv4Addr::new(((raw_addr >> 24) & 0xFF) as u8,
                                     ((raw_addr >> 16) & 0xFF) as u8,
                                     ((raw_addr >> 8) & 0xFF) as u8,
                                     ((raw_addr >> 0) & 0xFF) as u8);

            Ok(DnsRecord::A {
                domain: domain,
                addr: addr,
                ttl: ttl
            })
        },
```

The AAAA record type follows the same logic, but with more numbers to keep
track off.

```rust
        QueryType::AAAA => {
            let raw_addr1 = try!(buffer.read_u32());
            let raw_addr2 = try!(buffer.read_u32());
            let raw_addr3 = try!(buffer.read_u32());
            let raw_addr4 = try!(buffer.read_u32());
            let addr = Ipv6Addr::new(((raw_addr1 >> 16) & 0xFFFF) as u16,
                                     ((raw_addr1 >> 0) & 0xFFFF) as u16,
                                     ((raw_addr2 >> 16) & 0xFFFF) as u16,
                                     ((raw_addr2 >> 0) & 0xFFFF) as u16,
                                     ((raw_addr3 >> 16) & 0xFFFF) as u16,
                                     ((raw_addr3 >> 0) & 0xFFFF) as u16,
                                     ((raw_addr4 >> 16) & 0xFFFF) as u16,
                                     ((raw_addr4 >> 0) & 0xFFFF) as u16);

            Ok(DnsRecord::AAAA {
                domain: domain,
                addr: addr,
                ttl: ttl
            })
        },
```

NS and CNAME both have the same structure.

```rust
        QueryType::NS => {
            let mut ns = String::new();
            try!(buffer.read_qname(&mut ns));

            Ok(DnsRecord::NS {
                domain: domain,
                host: ns,
                ttl: ttl
            })
        },
        QueryType::CNAME => {
            let mut cname = String::new();
            try!(buffer.read_qname(&mut cname));

            Ok(DnsRecord::CNAME {
                domain: domain,
                host: cname,
                ttl: ttl
            })
        },
```

MX is close to the previous two, but with one extra field for priority.

```rust
        QueryType::MX => {
            let priority = try!(buffer.read_u16());
            let mut mx = String::new();
            try!(buffer.read_qname(&mut mx));

            Ok(DnsRecord::MX {
                domain: domain,
                priority: priority,
                host: mx,
                ttl: ttl
            })
        },
```

And we end with some code for handling unknown record types, as before.

```rust
        QueryType::UNKNOWN(_) => {
            try!(buffer.step(data_len as usize));

            Ok(DnsRecord::UNKNOWN {
                domain: domain,
                qtype: qtype_num,
                data_len: data_len,
                ttl: ttl
            })
        }
    }
}
```

It's a bit of a mouthful, but individually not much more complex than what we
had.

### Extending BytePacketBuffer for setting values in place

Before we move on to writing records, we'll have to add two more functions to
`BytePacketBuffer`:

```rust
impl BytePacketBuffer {

    - snip -

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        try!(self.set(pos,(val >> 8) as u8));
        try!(self.set(pos+1,(val & 0xFF) as u8));

        Ok(())
    }

}
```

### Extending DnsRecord for writing new record types

Now we can amend `DnsRecord::write`. Here's our new function:

```rust
pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {

    let start_pos = buffer.pos();

    match *self {
        DnsRecord::A { ref domain, ref addr, ttl } => {
            try!(buffer.write_qname(domain));
            try!(buffer.write_u16(QueryType::A.to_num()));
            try!(buffer.write_u16(1));
            try!(buffer.write_u32(ttl));
            try!(buffer.write_u16(4));

            let octets = addr.octets();
            try!(buffer.write_u8(octets[0]));
            try!(buffer.write_u8(octets[1]));
            try!(buffer.write_u8(octets[2]));
            try!(buffer.write_u8(octets[3]));
        },
        DnsRecord::NS { ref domain, ref host, ttl } => {
            try!(buffer.write_qname(domain));
            try!(buffer.write_u16(QueryType::NS.to_num()));
            try!(buffer.write_u16(1));
            try!(buffer.write_u32(ttl));

            let pos = buffer.pos();
            try!(buffer.write_u16(0));

            try!(buffer.write_qname(host));

            let size = buffer.pos() - (pos + 2);
            try!(buffer.set_u16(pos, size as u16));
        },
        DnsRecord::CNAME { ref domain, ref host, ttl } => {
            try!(buffer.write_qname(domain));
            try!(buffer.write_u16(QueryType::CNAME.to_num()));
            try!(buffer.write_u16(1));
            try!(buffer.write_u32(ttl));

            let pos = buffer.pos();
            try!(buffer.write_u16(0));

            try!(buffer.write_qname(host));

            let size = buffer.pos() - (pos + 2);
            try!(buffer.set_u16(pos, size as u16));
        },
        DnsRecord::MX { ref domain, priority, ref host, ttl } => {
            try!(buffer.write_qname(domain));
            try!(buffer.write_u16(QueryType::MX.to_num()));
            try!(buffer.write_u16(1));
            try!(buffer.write_u32(ttl));

            let pos = buffer.pos();
            try!(buffer.write_u16(0));

            try!(buffer.write_u16(priority));
            try!(buffer.write_qname(host));

            let size = buffer.pos() - (pos + 2);
            try!(buffer.set_u16(pos, size as u16));
        },
        DnsRecord::AAAA { ref domain, ref addr, ttl } => {
            try!(buffer.write_qname(domain));
            try!(buffer.write_u16(QueryType::AAAA.to_num()));
            try!(buffer.write_u16(1));
            try!(buffer.write_u32(ttl));
            try!(buffer.write_u16(16));

            for octet in &addr.segments() {
                try!(buffer.write_u16(*octet));
            }
        },
        DnsRecord::UNKNOWN { .. } => {
            println!("Skipping record: {:?}", self);
        }
    }

    Ok(buffer.pos() - start_pos)
}
```

Again, quite a bit of extra code, but thankfully the last thing we've got to
do. We're still not using the write part, but it'll come in handy once we write
our server.

### Testing the new record types

Now we're ready to retry our ''yahoo.com'' query:

```text
DnsHeader {
    id: 6666,
    recursion_desired: true,
    truncated_message: false,
    authoritative_answer: false,
    opcode: 0,
    response: true,
    rescode: NOERROR,
    checking_disabled: false,
    authed_data: false,
    z: false,
    recursion_available: true,
    questions: 1,
    answers: 3,
    authoritative_entries: 0,
    resource_entries: 0
}
DnsQuestion {
    name: "www.yahoo.com",
    qtype: A
}
CNAME {
    domain: "www.yahoo.com",
    host: "fd-fp3.wg1.b.yahoo.com",
    ttl: 3
}
A {
    domain: "fd-fp3.wg1.b.yahoo.com",
    addr: 46.228.47.115,
    ttl: 19
}
A {
    domain: "fd-fp3.wg1.b.yahoo.com",
    addr: 46.228.47.114,
    ttl: 19
}
```

For good measure, let's try doing an MX lookup as well:

```rust
let qname = "yahoo.com";
let qtype = QueryType::MX;
```

Which yields:

```text
- snip -
DnsQuestion {
    name: "yahoo.com",
    qtype: MX
}
MX {
    domain: "yahoo.com",
    priority: 1,
    host: "mta6.am0.yahoodns.net",
    ttl: 1794
}
MX {
    domain: "yahoo.com",
    priority: 1,
    host: "mta7.am0.yahoodns.net",
    ttl: 1794
}
MX {
    domain: "yahoo.com",
    priority: 1,
    host: "mta5.am0.yahoodns.net",
    ttl: 1794
}
```

Encouraging!

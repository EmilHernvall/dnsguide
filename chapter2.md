2 - Building a stub resolver
============================

While it's slightly satisfying to know that we're able to succesfully parse DNS
packets, it's not much use to just read them off disk. As our next step, we'll
use it to build a `stub resolver`, which is a DNS client that doesn't feature
any built-in support for recursive lookup and that will only work with a DNS
server that does. Later we'll implement an actual recursive resolver to lose
the need for a server.

### Extending BytePacketBuffer for writing

In order to be able to service a query, we need to be able to not just read
packets, but also write them. To do so, we'll need to extend `BytePacketBuffer`
with some additional methods:

```rust
impl BytePacketBuffer {

    - snip -

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        try!(self.write(val));

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        try!(self.write((val >> 8) as u8));
        try!(self.write((val & 0xFF) as u8));

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        try!(self.write(((val >> 24) & 0xFF) as u8));
        try!(self.write(((val >> 16) & 0xFF) as u8));
        try!(self.write(((val >> 8) & 0xFF) as u8));
        try!(self.write(((val >> 0) & 0xFF) as u8));

        Ok(())
    }
```

We'll also need a function for writing query names in labeled form:

```rust
    fn write_qname(&mut self, qname: &str) -> Result<()> {

        let split_str = qname.split('.').collect::<Vec<&str>>();

        for label in split_str {
            let len = label.len();
            if len > 0x34 {
                return Err(Error::new(ErrorKind::InvalidInput, "Single label exceeds 63 characters of length"));
            }

            try!(self.write_u8(len as u8));
            for b in label.as_bytes() {
                try!(self.write_u8(*b));
            }
        }

        try!(self.write_u8(0));

        Ok(())
    }

} // End of BytePacketBuffer
```

### Extending DnsHeader for writing

Building on our new functions we can extend our protocol representation
structs. Starting with `DnsHeader`:

```rust
impl DnsHeader {

    - snip -

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        try!(buffer.write_u16(self.id));

        try!(buffer.write_u8( ((self.recursion_desired as u8)) |
                              ((self.truncated_message as u8) << 1) |
                              ((self.authoritative_answer as u8) << 2) |
                              (self.opcode << 3) |
                              ((self.response as u8) << 7) as u8) );

        try!(buffer.write_u8( (self.rescode.clone() as u8) |
                              ((self.checking_disabled as u8) << 4) |
                              ((self.authed_data as u8) << 5) |
                              ((self.z as u8) << 6) |
                              ((self.recursion_available as u8) << 7) ));

        try!(buffer.write_u16(self.questions));
        try!(buffer.write_u16(self.answers));
        try!(buffer.write_u16(self.authoritative_entries));
        try!(buffer.write_u16(self.resource_entries));

        Ok(())
    }

}
```

### Extending DnsQuestion for writing

Moving on to `DnsQuestion`:

```rust
impl DnsQuestion {

    - snip -

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {

        try!(buffer.write_qname(&self.name));

        let typenum = self.qtype.to_num();
        try!(buffer.write_u16(typenum));
        try!(buffer.write_u16(1));

        Ok(())
    }

}
```

### Extending DnsRecord for writing

`DnsRecord` is for now quite compact as well, although we'll eventually add
quite a bit of code here to handle different record types:

```rust
impl DnsRecord {

    - snip -

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
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }

}
```

### Extending DnsPacket for writing

Putting it all together in `DnsPacket`:

```rust
impl DnsPacket {

    - snip -

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()>
    {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        try!(self.header.write(buffer));

        for question in &self.questions {
            try!(question.write(buffer));
        }
        for rec in &self.answers {
            try!(rec.write(buffer));
        }
        for rec in &self.authorities {
            try!(rec.write(buffer));
        }
        for rec in &self.resources {
            try!(rec.write(buffer));
        }

        Ok(())
    }

}
```

### Implementing a stub resolver

We're ready to implement our stub resolver. Rust includes a convenient
`UDPSocket` which does most of the work. First there's some house keeping:

```rust
fn main() {
    // Perform an A query for google.com
    let qname = "google.com";
    let qtype = QueryType::A;

    // Using googles public DNS server
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();
```


Next we'll build our query packet. It's important that we remember to set the
`recursion_desired` flag. As noted earlier, the packet id is arbitrary.

```rust
    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));
```

We can use our new write method to write the packet to a buffer...

```rust
        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer).unwrap();
```

...and send it off to the server using our socket:

```rust
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server).unwrap();
```

To prepare for receiving the response, we'll create a new `BytePacketBuffer`.
We'll then ask the socket to write the response directly into our buffer.

```rust
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();
```

As per the previous section, `DnsPacket::from_buffer()` is then used to
actually parse the packet after which we can print the response.

```rust
    let res_packet = DnsPacket::from_buffer(&mut res_buffer).unwrap();
    println!("{:?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:?}", q);
    }
    for rec in res_packet.answers {
        println!("{:?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:?}", rec);
    }
}
```

Running it will print:

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
    answers: 1,
    authoritative_entries: 0,
    resource_entries: 0
}
DnsQuestion {
    name: "google.com",
    qtype: A
}
A {
    domain: "google.com",
    addr: 216.58.209.110,
    ttl: 79
}
```

We're approaching something useful!

2 - Construire un résolveur de souche
=====================================

S'il est assez satisfaisant de savoir que nous sommes capables d'analyser des
paquets DNS, cela ne sert pas à grand-chose de se contenter de les lire depuis
le disque. Comme prochaine étape, nous allons nous en servir pour construire un
résolveur de souche (*stub resolver*), c'est-à-dire un client DNS qui ne gère
pas lui-même la résolution récursive et qui ne fonctionne qu'avec un serveur
DNS qui, lui, la gère. Plus tard, nous implémenterons un véritable résolveur
récursif pour nous passer de ce serveur.

### Étendre BytePacketBuffer pour l'écriture

Pour pouvoir traiter une requête, nous devons être capables non seulement de
lire des paquets, mais aussi de les écrire. Pour cela, il faut ajouter quelques
méthodes à `BytePacketBuffer` :

```rust
impl BytePacketBuffer {

    - snip -

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }
```

Il nous faut aussi une fonction pour écrire les noms recherchés sous forme de
labels :

```rust
    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

} // Fin de BytePacketBuffer
```

### Étendre DnsHeader pour l'écriture

En nous appuyant sur ces nouvelles fonctions, nous pouvons étendre les structs
qui représentent le protocole, en commençant par `DnsHeader` :

```rust
impl DnsHeader {

    - snip -

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }

}
```

### Étendre DnsQuestion pour l'écriture

Passons à `DnsQuestion` :

```rust
impl DnsQuestion {

    - snip -

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }

}
```

### Étendre DnsRecord pour l'écriture

`DnsRecord` reste lui aussi assez compact pour l'instant, même si nous finirons
par y ajouter pas mal de code pour gérer les différents types
d'enregistrements :

```rust
impl DnsRecord {

    - snip -

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }

}
```

### Étendre DnsPacket pour l'écriture

Assemblons le tout dans `DnsPacket` :

```rust
impl DnsPacket {

    - snip -

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

}
```

### Implémenter un résolveur de souche

Nous sommes prêts à implémenter notre résolveur de souche. Rust fournit un
`UDPSocket` bien pratique qui fait l'essentiel du travail.

```rust
fn main() -> Result<()> {
    // Effectue une requête A pour google.com
    let qname = "google.com";
    let qtype = QueryType::A;

    // Utilise le serveur DNS public de Google
    let server = ("8.8.8.8", 53);

    // Associe une socket UDP à un port arbitraire
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Construit notre paquet de requête. Il est important de ne pas oublier
    // de positionner le drapeau `recursion_desired`. Comme indiqué plus tôt,
    // l'identifiant du paquet est arbitraire.
    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    // Utilise notre nouvelle méthode write pour écrire le paquet dans un
    // tampon...
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // ...et l'envoie au serveur via notre socket :
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // Pour nous préparer à recevoir la réponse, nous créons un nouveau
    // `BytePacketBuffer` et demandons à la socket d'écrire la réponse
    // directement dans ce tampon.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // Comme dans la section précédente, `DnsPacket::from_buffer()` sert ensuite
    // à analyser le paquet, après quoi nous pouvons afficher la réponse.
    let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
```

L'exécution affiche :

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

Le prochain chapitre porte sur la prise en charge d'un éventail plus large de
types d'enregistrements :
[Chapitre 3 - Ajouter d'autres types d'enregistrements](chapter3.md)

4 - Notre tout premier serveur DNS
==================================

Arrivés jusqu'ici, nous sommes prêts à tenter d'écrire un véritable serveur.
Les serveurs DNS réels se déclinent en deux variantes :

 * Serveur faisant autorité (*Authoritative Server*) - Un serveur DNS qui
   héberge une ou plusieurs « zones ». Par exemple, les serveurs faisant
   autorité pour la zone google.com sont ns1.google.com, ns2.google.com,
   ns3.google.com et ns4.google.com.
 * Serveur cache (*Caching Server*) - Un serveur DNS qui traite les
   résolutions en vérifiant d'abord dans son cache s'il connaît déjà
   l'enregistrement demandé, et qui, dans le cas contraire, effectue une
   résolution récursive pour le trouver. C'est le cas du serveur DNS qui tourne
   probablement sur votre box, du serveur DNS que votre fournisseur d'accès
   vous attribue par DHCP, ou encore des serveurs DNS publics de Google,
   8.8.8.8 et 8.8.4.4.

À strictement parler, rien n'empêche un serveur de jouer les deux rôles, mais
en pratique ils sont généralement mutuellement exclusifs. Cela explique aussi
l'importance des drapeaux `RD` (*Recursion Desired*, récursion souhaitée) et
`RA` (*Recursion Available*, récursion disponible) dans l'en-tête du paquet :
un résolveur de souche qui interroge un serveur cache positionne le drapeau
`RD`, et comme le serveur accepte ce genre de requêtes, il effectue la
résolution et renvoie une réponse avec le drapeau `RA` positionné. Cela ne
fonctionne pas avec un serveur faisant autorité, qui ne répond qu'aux requêtes
concernant les zones qu'il héberge et renverra donc une erreur à toute requête
ayant le drapeau `RD` positionné.

Mais ne me croyez pas sur parole ! Vérifions-le. Commençons par utiliser
`8.8.8.8` pour résoudre *yahoo.com* :

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

Cela fonctionne comme prévu. Essayons maintenant d'envoyer la même requête à
l'un des serveurs qui hébergent la zone *google.com* :

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

Remarquez que le statut de la réponse est `REFUSED` ! `dig` nous avertit aussi
que, bien que le drapeau `RD` ait été positionné dans la requête, le serveur
n'a pas positionné le drapeau `RA` dans sa réponse. Nous pouvons en revanche
utiliser ce même serveur pour *google.com* :

```text
# dig @ns1.google.com google.com

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

Pas d'erreur cette fois, mais `dig` nous avertit toujours que la récursion
n'est pas disponible. Nous pouvons la désactiver explicitement avec
`+norecurse`, ce qui fait disparaître l'avertissement :

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

Cette dernière requête est le type de requête qu'on s'attend à voir envoyée
par un serveur cache lorsqu'il résout un nom de manière récursive.

Pour notre première incursion dans l'écriture de notre propre serveur, nous
allons faire encore plus simple en implémentant un serveur qui se contente de
transmettre les requêtes à un autre serveur cache, autrement dit un « serveur
DNS proxy ». Comme nous avons déjà fait l'essentiel du travail difficile, ce
sera plutôt rapide !

### Extraire la résolution dans une fonction dédiée

Commençons par une petite refactorisation en déplaçant notre code de
résolution dans une fonction séparée. Il s'agit pour l'essentiel du même code
que celui de notre fonction `main` du chapitre précédent.

```rust
fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // Transmet les requêtes au DNS public de Google
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    DnsPacket::from_buffer(&mut res_buffer)
}

```

### Implémenter notre premier serveur

Écrivons maintenant le code de notre serveur. Il faut d'abord mettre
quelques éléments en place.

```rust
/// Traite un paquet entrant
fn handle_query(socket: &UdpSocket) -> Result<()> {
    // Avec une socket prête, nous pouvons lire un paquet. L'appel bloque
    // jusqu'à ce qu'un paquet soit reçu.
    let mut req_buffer = BytePacketBuffer::new();

    // La fonction `recv_from` écrit les données dans le tampon fourni et
    // renvoie la longueur des données lues ainsi que l'adresse source. La
    // longueur ne nous intéresse pas, mais nous devons garder la source pour
    // pouvoir envoyer notre réponse plus tard.
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    // Ensuite, `DnsPacket::from_buffer` sert à transformer les octets bruts
    // en `DnsPacket`.
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    // Crée et initialise le paquet de réponse
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    // Dans le cas normal, il y a exactement une question
    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        // Puisque tout est en place et conforme aux attentes, la requête
        // peut être transmise au serveur cible. Il est toujours possible que
        // la requête échoue, auquel cas le code de réponse `SERVFAIL` est
        // positionné pour l'indiquer au client. Si au contraire tout se passe
        // comme prévu, la question et les enregistrements de réponse sont
        // copiés dans notre paquet de réponse.
        if let Ok(result) = lookup(&question.name, question.qtype) {
            packet.questions.push(question);
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
    }
    // Sachant à quel point les données reçues d'émetteurs quelconques
    // peuvent être peu fiables, nous devons nous assurer qu'une question est
    // bien présente. Sinon, nous renvoyons `FORMERR` pour indiquer que
    // l'émetteur a commis une erreur.
    else {
        packet.header.rescode = ResultCode::FORMERR;
    }

    // Il ne reste plus qu'à encoder notre réponse et à l'envoyer !
    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}

fn main() -> Result<()> {
    // Associe une socket UDP au port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // Pour l'instant, les requêtes sont traitées séquentiellement : on lance
    // donc une boucle infinie pour servir les requêtes.
    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
```

L'idiome `match` pour la gestion des erreurs est utilisé encore et encore ici,
car nous voulons à tout prix éviter d'interrompre notre boucle de traitement
des requêtes. C'est un peu verbeux, et nous préférerions normalement utiliser
`try!`. Malheureusement, ce n'est pas possible ici, puisque nous sommes dans la
fonction `main`, qui ne renvoie pas de `Result`.

C'est terminé ! Essayons-le. Nous démarrons notre serveur dans un terminal et
utilisons `dig` pour effectuer une résolution dans un second terminal.

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

Dans le terminal du serveur, on voit :

```text
Received query: DnsQuestion { name: "google.com", qtype: A }
Answer: A { domain: "google.com", addr: 216.58.211.142, ttl: 96 }
```

Victoire ! En moins de 800 lignes de code, nous avons construit un serveur DNS
capable de répondre à des requêtes portant sur plusieurs types
d'enregistrements !

Dans le prochain chapitre, nous nous affranchirons de notre dépendance à un
résolveur existant :
[Chapitre 5 - Résolution récursive](chapter5.md)

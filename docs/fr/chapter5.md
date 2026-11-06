5 - Résolution récursive
========================

Notre serveur fonctionne, mais dépendre d'un autre serveur pour effectuer
réellement la résolution est agaçant et peu utile. C'est le bon moment pour
entrer dans le détail de la manière dont un nom est réellement résolu.

En supposant qu'aucune information ne soit connue au préalable, la question
est d'abord posée à l'un des 13 serveurs racine (*root servers*) d'Internet.
Pourquoi 13 ? Parce que c'est le nombre qui tient dans un paquet DNS de 512
octets (à strictement parler, il y a de la place pour 14, mais une marge a été
conservée). Vous pourriez penser que 13, c'est un peu juste pour gérer tout
Internet, et vous auriez raison : il y a 13 serveurs logiques, mais bien plus
en réalité. Vous pouvez en apprendre davantage
[ici](http://www.root-servers.org/). Tout résolveur doit connaître ces 13
serveurs à l'avance. Un fichier les contenant tous, au format bind, est
disponible sous le nom [named.root](https://www.internic.net/domain/named.root).
Ces serveurs contiennent tous les mêmes informations, et pour commencer nous
pouvons en choisir un au hasard. En regardant `named.root`, on voit que
l'adresse IP de *a.root-servers.net* est 198.41.0.4 ; utilisons-la donc pour
effectuer notre première requête pour *www.google.com*.

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

Les serveurs racine ne connaissent pas *www.google.com*, mais ils connaissent
*com* : leur réponse nous indique donc où aller ensuite. Quelques points sont à
noter :

 * On nous fournit un ensemble d'enregistrements NS, situés dans la section
   Autorité. Les enregistrements NS nous donnent *le nom* du serveur de noms
   qui gère un domaine.
 * Le serveur a l'obligeance de nous transmettre les enregistrements A
   correspondant aux enregistrements NS, ce qui nous évite une seconde
   résolution.
 * Nous n'avons pas vraiment demandé *com*, mais *www.google.com*. Pourtant,
   les enregistrements NS font tous référence à *com*.

Choisissons un serveur dans le résultat et continuons. *192.5.6.30*, pour
*a.gtld-servers.net*, fera aussi bien l'affaire qu'un autre.

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

Nous ne sommes toujours pas arrivés à *www.google.com*, mais nous disposons
au moins maintenant d'un ensemble de serveurs qui gèrent le domaine
*google.com*. Faisons une nouvelle tentative en envoyant notre requête à
*216.239.32.10*.

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

Et voilà ! L'IP de *www.google.com*, comme souhaité. Récapitulons :

 * *a.root-servers.net* nous dit d'interroger *a.gtld-servers.net*, qui gère
   com
 * *a.gtld-servers.net* nous dit d'interroger *ns1.google.com*, qui gère
   google.com
 * *ns1.google.com* nous donne l'IP de *www.google.com*

C'est un cas plutôt typique, et la plupart des résolutions ne nécessiteront
jamais que trois étapes, même sans cache. Il est cependant possible d'avoir
des serveurs de noms pour des sous-domaines, et d'autres encore pour des
sous-sous-domaines. En pratique, un serveur DNS maintient un cache, et la
plupart des TLD sont déjà connus. Cela signifie que la plupart des requêtes ne
demanderont au serveur que deux résolutions, et souvent une seule, voire
aucune.

### Étendre DnsPacket pour les résolutions récursives

Avant d'aller plus loin, nous avons besoin de quelques fonctions utilitaires
sur `DnsPacket`.

```rust
impl DnsPacket {

    - snip -

    /// Il est utile de pouvoir choisir un enregistrement A au hasard dans un
    /// paquet. Lorsque nous obtenons plusieurs IP pour un même nom, peu
    /// importe laquelle nous choisissons : dans ces cas-là, nous pouvons
    /// désormais en prendre une au hasard.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }

    /// Une fonction utilitaire qui renvoie un itérateur sur tous les serveurs
    /// de noms de la section Autorité, sous forme de tuples (domaine, hôte)
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            // En pratique, ce sont toujours des enregistrements NS dans des
            // paquets bien formés. On convertit les enregistrements NS en
            // tuples ne contenant que les données utiles, pour les manipuler
            // plus facilement.
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            // Écarte les serveurs qui ne font pas autorité pour notre requête
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// Nous tirons parti du fait que les serveurs de noms joignent souvent
    /// les enregistrements A correspondants lorsqu'ils répondent à une
    /// requête NS, pour implémenter une fonction qui renvoie, si possible,
    /// l'IP réelle d'un enregistrement NS.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        // Récupère un itérateur sur les serveurs de noms de la section Autorité
        self.get_ns(qname)
            // Il faut maintenant chercher un enregistrement A correspondant
            // dans la section Additionnelle. Comme nous voulons simplement le
            // premier enregistrement valide, il suffit de construire un flux
            // d'enregistrements correspondants.
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    // Garde les enregistrements A dont le domaine correspond
                    // à l'hôte de l'enregistrement NS en cours de traitement
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            // Enfin, choisit la première entrée valide
            .next()
    }

    /// Cependant, tous les serveurs de noms ne sont pas aussi aimables. Dans
    /// certains cas, il n'y aura aucun enregistrement A dans la section
    /// Additionnelle, et nous devrons effectuer *une autre* résolution en
    /// cours de route. Pour cela, nous ajoutons une méthode qui renvoie le nom
    /// d'hôte d'un serveur de noms approprié.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        // Récupère un itérateur sur les serveurs de noms de la section Autorité
        self.get_ns(qname)
            .map(|(_, host)| host)
            // Enfin, choisit la première entrée valide
            .next()
    }

} // Fin de DnsPacket
```

### Implémenter la résolution récursive

Passons sans tarder à notre nouvelle fonction `recursive_lookup` :

```rust
fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // Pour l'instant, nous commençons toujours par *a.root-servers.net*.
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    // Comme cela peut prendre un nombre arbitraire d'étapes, nous entrons
    // dans une boucle sans limite.
    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        // L'étape suivante consiste à envoyer la requête au serveur actif.
        let ns_copy = ns;

        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        // S'il y a des entrées dans la section Réponse et aucune erreur,
        // nous avons terminé !
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        // Nous pouvons aussi recevoir une réponse `NXDOMAIN`, qui est la
        // manière dont les serveurs de noms faisant autorité nous indiquent
        // que le nom n'existe pas.
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // Sinon, nous essayons de trouver un nouveau serveur de noms à partir
        // d'un NS et de l'enregistrement A correspondant dans la section
        // Additionnelle. Si cela réussit, nous pouvons changer de serveur de
        // noms et relancer la boucle.
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;

            continue;
        }

        // Sinon, nous devons résoudre l'IP d'un enregistrement NS. S'il n'y a
        // aucun enregistrement NS, nous nous en tenons à ce que le dernier
        // serveur nous a répondu.
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        // C'est ici que nous descendons dans le terrier du lapin, en lançant
        // une _autre_ séquence de résolution au milieu de la séquence
        // courante. Avec un peu de chance, elle nous donnera l'IP d'un
        // serveur de noms approprié.
        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

        // Enfin, nous choisissons une IP au hasard dans le résultat et
        // relançons la boucle. Si aucun enregistrement de ce type n'est
        // disponible, nous renvoyons là encore le dernier résultat obtenu.
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}
```

Cela nécessite aussi une petite modification de la fonction `lookup`, puisque
nous devons lui indiquer quel serveur utiliser. Nous ajoutons un paramètre
`server` à la signature de la fonction et supprimons la variable `server` codée
en dur que nous utilisions au chapitre 4 :

```rust
fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
```

### Essayer la résolution récursive

Il ne reste plus qu'à modifier notre fonction `handle_query` pour qu'elle
utilise `recursive_lookup` :

```rust
fn handle_query(socket: &UdpSocket) -> Result<()> {

    - snip -

            println!("Received query: {:?}", question);
            if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
                packet.questions.push(question.clone());
                packet.header.rescode = result.header.rescode;

    - snip -

}
```

Essayons !

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

Dans la fenêtre du serveur, on voit :

```text
Received query: DnsQuestion { name: "www.google.com", qtype: A }
attempting lookup of A www.google.com with ns 198.41.0.4
attempting lookup of A www.google.com with ns 192.12.94.30
attempting lookup of A www.google.com with ns 216.239.34.10
Answer: A { domain: "www.google.com", addr: 216.58.211.132, ttl: 300 }
```

Cela reproduit la démarche manuelle que nous avons suivie plus tôt. Nous
savons maintenant résoudre un domaine en partant de la liste des serveurs
racine. Nous disposons désormais d'un serveur DNS pleinement fonctionnel,
quoique perfectible.

Il y a beaucoup de choses que nous pourrions améliorer. Par exemple, ce
serveur n'offre aucune véritable concurrence. Il ne peut ni envoyer ni
recevoir de requêtes en TCP. Nous ne pouvons pas l'utiliser pour héberger nos
propres zones et le faire fonctionner comme serveur faisant autorité.
L'absence de prise en charge de DNSSEC nous expose à des attaques
d'empoisonnement DNS (*DNS poisoning*), dans lesquelles un serveur malveillant
peut renvoyer des enregistrements concernant le domaine de quelqu'un d'autre.

Bon nombre de ces problèmes ont été corrigés dans mon propre projet
[hermes](https://github.com/EmilHernvall/hermes) : vous pouvez donc aller voir
comment je m'y suis pris, ou poursuivre seul à partir d'ici. À moins que vous
n'ayez eu votre dose de DNS pour l'instant... :) Quoi qu'il en soit, j'espère
que ce guide vous aura permis de mieux comprendre le fonctionnement de DNS.

#include "network.hpp"

#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <errno.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <assert.h>
#include <algorithm>

static void unix_time_update() { /* FIXME */ }

static uint64_t current_time_actual(void) { /* FIXME */ return 0; }

int networking_at_startup(void) { /* FIXME */ return 0; }

uint64_t current_time_monotonic(void) { /* FIXME */ return 0; }

bool IP4::operator==(const IP4& other) const {
    return in_addr.s_addr == other.in_addr.s_addr;
}

bool IP6::operator==(const IP6& other) const {
    return uint64[0] == other.uint64[0] && uint64[1] == other.uint64[1];
}

bool IP6::contains_ipv4() const
{
    // IPv4 address in IPv6?
    return uint64[0] == 0 && uint32[2] == htonl(0xffff);
}

bool IP4::operator==(const IP6& other) const {
    if (other.contains_ipv4())
        return uint32 == other.uint32[3];
    return false;
}

bool IP6::operator==(const IP4& other) const {
    return other == *this;
}

bool IP::operator==(const IP& other) const
{
    const IP& self = *this;

    bool self_v4 = self.family == AF_INET;
    bool self_v6 = self.family == AF_INET6;
    bool other_v4 = other.family == AF_INET;
    bool other_v6 = other.family == AF_INET6;

    if (self_v4 && other_v4)
        return self.ip4 == other.ip4;
    else if (self_v4 && other_v6)
        return self.ip4 == other.ip6;
    else if (self_v6 && other_v4)
        return self.ip6 == other.ip4;
    else if (self_v6 && other_v6)
        return self.ip6 == other.ip6;
    else
        return false;
}

IP6 IP4::to_ip6() const
{
    IP6 ip6;
    ip6.uint32[0] = 0;
    ip6.uint32[1] = 0;
    ip6.uint32[2] = htonl(0xFFFF);
    ip6.uint32[3] = this->uint32;
    return ip6;
}


IP IP::create_ip4()
{
    IP result = IP();
    result.family = AF_INET;
    return result;
}

IP IP::create_ip6()
{
    IP result = IP();
    result.family = AF_INET6;
    return result;
}

IP IP::create(bool ipv6enabled)
{
    return ipv6enabled ? create_ip6() : create_ip4();
}


bool IP::isset() const {
    return family != 0;
}


IP_Port::IP_Port() : ip(), port() { }

bool IP_Port::operator==(const IP_Port& other) const {
    return port == other.port && ip == other.ip;
}

bool IP_Port::isset() const {
    return port != 0 && ip.isset();
}

sockaddr_storage IP_Port::to_addr_4(const IP_Port& self)
{
    assert(self.ip.family == AF_INET);
    sockaddr_storage storage;
    sockaddr_in* addr = reinterpret_cast<sockaddr_in*>( &storage );

    addr->sin_family = AF_INET;
    addr->sin_addr = self.ip.ip4.in_addr;
    addr->sin_port = self.port;

    return storage;
}

sockaddr_storage IP_Port::to_addr_6(const IP_Port& self)
{
    assert(self.ip.family != 0);
    const IP6& ip_addr = (self.ip.family == AF_INET6) ? self.ip.ip6 : self.ip.ip4.to_ip6();
    sockaddr_storage storage;
    sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>( &storage );

    addr->sin6_family = AF_INET6;
    addr->sin6_port = self.port;
    addr->sin6_addr = ip_addr.in6_addr;
    addr->sin6_flowinfo = 0;
    addr->sin6_scope_id = 0;

    return storage;
}

IP_Port IP_Port::from_addr(const sockaddr_storage& addr)
{
    IP_Port ip_port;
    if (addr.ss_family == AF_INET) {
        sockaddr_in* addr_in = (sockaddr_in*) &addr;
        ip_port.ip.family = addr_in->sin_family;
        ip_port.ip.ip4.in_addr = addr_in->sin_addr;
        ip_port.port = addr_in->sin_port;
    } else if (addr.ss_family == AF_INET6) {
        sockaddr_in6* addr_in = (sockaddr_in6*) &addr;
        ip_port.ip.family = addr_in->sin6_family;
        ip_port.ip.ip6.in6_addr = addr_in->sin6_addr;
        ip_port.port = addr_in->sin6_port;

        if (ip_port.ip.ip6.contains_ipv4()) {
            ip_port.ip.family = AF_INET;
            ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
        }
    }
    return ip_port;
}


Socket::Socket() : fd() { }

Socket::Socket(sa_family_t family, size_t tx_rx_buff_size)
    : fd()
{
    fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void*) &tx_rx_buff_size, sizeof(tx_rx_buff_size));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void*) &tx_rx_buff_size, sizeof(tx_rx_buff_size));

    /* Enable broadcast on socket */
    int broadcast = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast));
}


bool Socket::is_valid() const {
    if (fd < 0) {
        return false;
    }

    return true;
}

void Socket::kill() const {
    close(fd);
}

int Socket::bind(const IP_Port& ip_port) const
{
    sockaddr_storage addr;
    size_t addrsize;

    if (ip_port.ip.family == AF_INET) {
        addr = IP_Port::to_addr_4( ip_port );
        addrsize = sizeof(sockaddr_in);
    } else if (ip_port.ip.family == AF_INET6) {
        addr = IP_Port::to_addr_6( ip_port );
        addrsize = sizeof(sockaddr_in6);
    }
    return ::bind(fd, (sockaddr*) &addr, addrsize);
}


int Socket::sendto(uint8_t socket_family, IP_Port target, const void* data, size_t length, int flags) const
{
    if (socket_family == 0 || !(socket_family == AF_INET || socket_family == AF_INET6)) {
        /* Socket not initialized */
        /* Unknown address type*/
        return -1;
    }

    if (!target.isset())
        return -1;

    /* socket AF_INET, but target IP NOT: can't send */
    if (socket_family == AF_INET && target.ip.family != AF_INET)
        return -1;

    sockaddr_storage addr;
    size_t addrsize = 0;

    if (socket_family == AF_INET6) {
        addr = IP_Port::to_addr_6(target);
        addrsize = sizeof(sockaddr_in6);
    } else if (socket_family == AF_INET) {
        addr = IP_Port::to_addr_4(target);
        addrsize = sizeof(sockaddr_in);
    }

    int res = ::sendto(fd, data, length, flags, reinterpret_cast<sockaddr*>(&addr), addrsize);
    return res;
}

int Socket::recvfrom(IP_Port* ip_port, void* data, uint32_t* length, size_t max_len, int flags) const
{
    *ip_port = IP_Port();
    *length = 0;

    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    int fail_or_len = ::recvfrom(fd, data, max_len, flags, (sockaddr*) &addr, &addrlen);

    if (fail_or_len < 0) {
        return -1; /* Nothing received. */
    }

    *length = fail_or_len;
    if (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
        *ip_port = IP_Port::from_addr(addr);
    } else
        return -1;

    return 0;
}

bool Socket::set_nonblock() const {
    return fcntl(fd, F_SETFL, O_NONBLOCK, 1) == 0;
}

bool Socket::set_nosigpipe() const {
    return 1;
}

bool Socket::set_reuseaddr() const {
    int set = 1;
    return (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*) &set, sizeof(set)) == 0);
}

bool Socket::set_dualstack() const
{
    int ipv6only = 0;
    socklen_t optsize = sizeof(ipv6only);
    int res = getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &ipv6only, &optsize);

    if ((res == 0) && (ipv6only == 0))
        return true;

    ipv6only = false;
    return (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &ipv6only, sizeof(ipv6only)) == 0);
}


Networking_Core::Networking_Core() :
    packethandlers(), family(), port(), sock()
{

}

Networking_Core::~Networking_Core()
{
    if (family != 0)
        kill_sock(sock.fd);
}

void Networking_Core::poll() const
{
    if (family == 0) /* Socket not initialized */
        return;

    unix_time_update();

    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;

    while (sock.recvfrom(&ip_port, data, &length, MAX_UDP_PACKET_SIZE, /*flags*/ 0) != -1)
    {
        if (length < 1) continue;

        uint8_t handler_id = data[0];
        const Packet_Handler& handler = packethandlers[handler_id];

        if (!handler.function) {
            //LOGGER_WARNING("[%02u] -- Packet has no handler", data[0]);
            continue;
        } else {
            handler.function(handler.object, ip_port, data, length);
        }
    }
}


int sock_valid(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    return socket.is_valid();
}

void kill_sock(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    socket.kill();
}

int set_socket_nonblock(sock_t sock) {
    Socket socket;
    socket.fd = sock;
    return socket.set_nonblock();
}

int set_socket_nosigpipe(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    return socket.set_nosigpipe();
}

int set_socket_reuseaddr(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    return socket.set_reuseaddr();
}

int set_socket_dualstack(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    return socket.set_dualstack();
}

int sendpacket(Networking_Core* net, IP_Port ip_port, const uint8_t* data, uint16_t length)
{
    return net->sock.sendto(net->family, ip_port, data, length, /*flags*/ 0);
}

static int receivepacket(sock_t sock, IP_Port* ip_port, void* data, uint32_t* length)
{
    Socket socket;
    socket.fd = sock;
    return socket.recvfrom(ip_port, data, length, MAX_UDP_PACKET_SIZE, 0);
}

void networking_registerhandler(Networking_Core* net, uint8_t byte, packet_handler_callback cb, void* object)
{
    Packet_Handler& handler = net->packethandlers[byte];
    handler.function = cb;
    handler.object = object;
}

void networking_poll(Networking_Core* net)
{
    net->poll();
}

Networking_Core* new_networking(IP ip, uint16_t port)
{
    return new_networking_ex(ip, port, port + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM), 0);
}

Networking_Core* new_networking_ex(IP ip, uint16_t port_from, uint16_t port_to, unsigned int* error)
{
    /* If both from and to are 0, use default port range
     * If one is 0 and the other is non-0, use the non-0 value as only port
     * If from > to, swap
     */
    if (port_from == 0 && port_to == 0) {
        port_from = TOX_PORTRANGE_FROM;
        port_to = TOX_PORTRANGE_TO;
    } else if (port_from == 0 && port_to != 0) {
        port_from = port_to;
    } else if (port_from != 0 && port_to == 0) {
        port_to = port_from;
    } else if (port_from > port_to) {
        uint16_t temp = port_from;
        port_from = port_to;
        port_to = temp;
    }

    if (error)
        *error = 2;

    /* maybe check for invalid IPs like 224+.x.y.z? if there is any IP set ever */
    if (ip.family != AF_INET && ip.family != AF_INET6) {
        // Invalid address family
        return NULL;
    }

    if (networking_at_startup() != 0)
        return NULL;

    Networking_Core* temp = new Networking_Core();

    temp->family = ip.family;
    temp->port = 0;

    size_t tx_rx_buff_size = 1024 * 1024 * 2;
    temp->sock = Socket(temp->family, tx_rx_buff_size);

    /* Check for socket error. */
    if ( !temp->sock.is_valid() ) {
        kill_networking(temp);

        if (error)
            *error = 1;

        return NULL;
    }

    /* iOS UDP sockets are weird and apparently can SIGPIPE */
    if ( !temp->sock.set_nosigpipe() ) {
        kill_networking(temp);

        if (error)
            *error = 1;

        return NULL;
    }

    /* Set socket nonblocking. */
    if ( !temp->sock.set_nonblock() ) {
        kill_networking(temp);

        if (error)
            *error = 1;

        return NULL;
    }

    if (ip.family == AF_INET6) {
        temp->sock.set_dualstack();

        ipv6_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xFF;
        mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
        mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
        mreq.ipv6mr_interface = 0;

        setsockopt(temp->sock.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));

       // LOGGER_DEBUG(res < 0 ? "Failed to activate local multicast membership. (%u, %s)" :
       //              "Local multicast group FF02::1 joined successfully", errno, strerror(errno) );
    }

    /* a hanging program or a different user might block the standard port;
     * as long as it isn't a parameter coming from the commandline,
     * try a few ports after it, to see if we can find a "free" one
     *
     * if we go on without binding, the first sendto() automatically binds to
     * a free port chosen by the system (i.e. anything from 1024 to 65535)
     *
     * returning NULL after bind fails has both advantages and disadvantages:
     * advantage:
     *   we can rely on getting the port in the range 33445..33450, which
     *   enables us to tell joe user to open their firewall to a small range
     *
     * disadvantage:
     *   some clients might not test return of tox_new(), blindly assuming that
     *   it worked ok (which it did previously without a successful bind)
     */

    /* Bind our socket to port PORT and the given IP address (usually 0.0.0.0 or ::) */
    IP_Port ip_port;
    ip_port.ip = ip;
    uint16_t port_to_try = port_from;

    for (int tries = 0; tries <= std::max(port_to-port_from, 10); tries++, port_to_try++) {
        if (port_to_try > port_to)
            port_to_try = port_from;
        ip_port.port = htons(port_to_try);

        int res = temp->sock.bind(ip_port);

        if (!res) {
            temp->port = ip_port.port;

            //LOGGER_DEBUG("Bound successfully to %s:%u", ip_ntoa(&ip), ntohs(temp->port));

            /* errno isn't reset on success, only set on failure, the failed
             * binds with parallel clients yield a -EPERM to the outside if
             * errno isn't cleared here */
            errno = 0;

            if (error)
                *error = 0;

            return temp;
        }
    }

    //LOGGER_ERROR("Failed to bind socket: %u, %s IP: %s port_from: %u port_to: %u", errno, strerror(errno),
    //             ip_ntoa(&ip), port_from, port_to);

    kill_networking(temp);

    if (error)
        *error = 1;

    return NULL;
}

/* Function to cleanup networking stuff. */
void kill_networking(Networking_Core* net)
{
    delete net;
    return;
}


int ip_equal(const IP* a, const IP* b) {
    if (!a || !b)
        return 0;

    return *a == *b;
}

void ip_reset(IP* ip) {
    if (!ip)
        return;

    *ip = IP();
}

void ip_init(IP* ip, uint8_t ipv6enabled) {
    if (!ip)
        return;

    *ip = IP::create(ipv6enabled);
}

int ip_isset(const IP* ip) {
    if (!ip)
        return 0;

    return ip->isset();
}

void ip_copy(IP* target, const IP* source)
{
    if (!source || !target)
        return;

    *target = *source;
}

int ipport_equal(const IP_Port* a, const IP_Port* b) {
    if (!a || !b || !a->port)
        return 0;

    return *a == *b;
}

int ipport_isset(const IP_Port* ipport)
{
    if (!ipport || !ipport->port)
        return 0;

    return ipport->ip.isset();
}

void ipport_copy(IP_Port* target, const IP_Port* source)
{
    if (!source || !target)
        return;

    *target = *source;
}

int ip_parse_addr(const IP* ip, char* address, size_t length)
{
    if (!address || !ip) {
        return 0;
    }

    void* addr = NULL;
    if (ip->family == AF_INET) {
        addr = (in_addr*) &ip->ip4;
    } else if (ip->family == AF_INET6) {
        addr = (in6_addr*) &ip->ip6;
    }
    return inet_ntop(ip->family, addr, address, length) != NULL;
}

static char addresstext[96];
const char* ip_ntoa(const IP* ip)
{
    if (!ip) {
        snprintf(addresstext, sizeof(addresstext), "(IP invalid: NULL)");
        return addresstext;
    }

    char converted[INET6_ADDRSTRLEN];
    size_t converted_size = sizeof(converted);
    int ret = ip_parse_addr(ip, converted, converted_size);
    if (ret == 0) {
        snprintf(addresstext, sizeof(addresstext), "(IP invalid, %s)", strerror(errno));
        return addresstext;
    }

    if (ip->family == AF_INET) {
        /* returns standard quad-dotted notation */
        snprintf(addresstext, sizeof(addresstext), "%s", converted);
        return addresstext;
    } else if (ip->family == AF_INET6) {
        /* returns hex-groups enclosed into square brackets */
        snprintf(addresstext, sizeof(addresstext), "[%s]", converted);
        return addresstext;
    }
}

int addr_parse_ip(const char *address, IP *to)
{
    if (!address || !to)
        return 0;

    in_addr addr4;

    if (1 == inet_pton(AF_INET, address, &addr4)) {
        to->family = AF_INET;
        to->ip4.in_addr = addr4;
        return 1;
    }

    in6_addr addr6;

    if (1 == inet_pton(AF_INET6, address, &addr6)) {
        to->family = AF_INET6;
        to->ip6.in6_addr = addr6;
        return 1;
    }

    return 0;
}

int addr_resolve(const char* address, IP* to, IP* extra)
{
    if (!address || !to)
        return 0;

    sa_family_t family = to->family;

    addrinfo *server = NULL;
    addrinfo *walker = NULL;
    addrinfo  hints;
    int              rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

    if (networking_at_startup() != 0)
        return 0;

    rc = getaddrinfo(address, NULL, &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

    IP4 ip4;
    IP6 ip6;

    for (walker = server; (walker != NULL) && (rc != 3); walker = walker->ai_next) {
        switch (walker->ai_family) {
            case AF_INET: {
                if (walker->ai_family == family) { /* AF_INET requested, done */
                    sockaddr_in* addr = (sockaddr_in*) walker->ai_addr;
                    to->ip4.in_addr = addr->sin_addr;
                    rc = 3;
                } else if (!(rc & 1)) { /* AF_UNSPEC requested, store away */
                    sockaddr_in* addr = (sockaddr_in*) walker->ai_addr;
                    ip4.in_addr = addr->sin_addr;
                    rc |= 1;
                }
            } break;

            case AF_INET6: {
                if (walker->ai_family == family) { /* AF_INET6 requested, done */
                    if (walker->ai_addrlen == sizeof(sockaddr_in6)) {
                        sockaddr_in6* addr = (sockaddr_in6*) walker->ai_addr;
                        to->ip6.in6_addr = addr->sin6_addr;
                        rc = 3;
                    }
                } else if (!(rc & 2)) { /* AF_UNSPEC requested, store away */
                    if (walker->ai_addrlen == sizeof(sockaddr_in6)) {
                        sockaddr_in6* addr = (sockaddr_in6*) walker->ai_addr;
                        ip6.in6_addr = addr->sin6_addr;
                        rc |= 2;
                    }
                }
            } break;
        }
    }

    if (to->family == AF_UNSPEC) {
        if (rc & 2) {
            to->family = AF_INET6;
            to->ip6 = ip6;

            if ((rc & 1) && (extra != NULL)) {
                extra->family = AF_INET;
                extra->ip4 = ip4;
            }
        } else if (rc & 1) {
            to->family = AF_INET;
            to->ip4 = ip4;
        } else
            rc = 0;
    }

    freeaddrinfo(server);
    return rc;
}

int addr_resolve_or_parse_ip(const char* address, IP* to, IP* extra)
{
    if (!addr_resolve(address, to, extra))
        if (!addr_parse_ip(address, to))
            return 0;

    return 1;
}

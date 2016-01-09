#include <gtest/gtest.h>
#include <toxcore/network.hpp>

TEST(IP, from_string)
{
    {
        SCOPED_TRACE("null ptr");
        IP ip;

        ASSERT_EQ(0, addr_parse_ip("127.0.0.1", NULL));
        ASSERT_EQ(0, addr_parse_ip(NULL, &ip));
        ASSERT_EQ(0, addr_parse_ip(NULL, NULL));
    }
    {
        SCOPED_TRACE("bad ip");
        std::vector<std::string> ips;
        ips.push_back("");
        ips.push_back(" ");
        ips.push_back("1271.0.0.1");
        ips.push_back("1.1.1");
        ips.push_back("127.1");
        ips.push_back("o.0.0.0");
        for(size_t i = 0; i < ips.size(); ++i)
        {
            std::string ip_str = ips[i];
            SCOPED_TRACE(ip_str);
            IP ip;
            ASSERT_EQ(0, addr_parse_ip(ip_str.c_str(), &ip));
        }
    }
    {
        SCOPED_TRACE("good ip4");
        std::vector<std::string> ips;
        ips.push_back("0.0.0.0");
        ips.push_back("127.0.0.1");
        for(size_t i = 0; i < ips.size(); ++i)
        {
            std::string ip_str = ips[i];
            SCOPED_TRACE(ip_str);
            IP ip;
            ASSERT_EQ(1, addr_parse_ip(ip_str.c_str(), &ip));
            ASSERT_EQ(AF_INET, ip.family);
        }
    }
    {
        SCOPED_TRACE("good ip6");
        std::vector<std::string> ips;
        ips.push_back("::");
        ips.push_back("::1");
        ips.push_back("::FFFF:204.152.189.116");
        ips.push_back("2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d");
        for(size_t i = 0; i < ips.size(); ++i)
        {
            std::string ip_str = ips[i];
            SCOPED_TRACE(ip_str);
            IP ip;
            ASSERT_EQ(1, addr_parse_ip(ip_str.c_str(), &ip));
            ASSERT_EQ(AF_INET6, ip.family);
        }
    }
}

TEST(IP, to_string)
{
    {
        SCOPED_TRACE("buffer does not have enough size");
        IP ip;
        ip_init(&ip, false);

        {
            SCOPED_TRACE("not enough size");
            char converted[4];
            size_t converted_size = sizeof(converted);
            ASSERT_EQ(0, ip_parse_addr(&ip, converted, converted_size));
        }
        {
            SCOPED_TRACE("enough size");
            char converted[42];
            size_t converted_size = sizeof(converted);
            ASSERT_EQ(1, ip_parse_addr(&ip, converted, converted_size));
        }
    }
    {
        SCOPED_TRACE("null ptr");
        IP ip;
        ip_init(&ip, false);
        char converted[INET6_ADDRSTRLEN];
        size_t converted_size = sizeof(converted);

        ASSERT_EQ(0, ip_parse_addr(NULL, converted, converted_size));
        ASSERT_EQ(0, ip_parse_addr(&ip, NULL, converted_size));
        ASSERT_EQ(0, ip_parse_addr(NULL, NULL, converted_size));
    }
    {
        SCOPED_TRACE("good ips");
        std::vector<std::string> ips;
        ips.push_back("0.0.0.0");
        ips.push_back("127.0.0.1");
        ips.push_back("::");
        ips.push_back("::1");
        for(size_t i = 0; i < ips.size(); ++i)
        {
            std::string ip_str = ips[i];
            SCOPED_TRACE(ip_str);
            IP ip;
            ASSERT_EQ(1, addr_parse_ip(ip_str.c_str(), &ip) );
            char converted[INET6_ADDRSTRLEN];
            ASSERT_EQ(1, ip_parse_addr(&ip, converted, sizeof(converted)) );
            ASSERT_EQ(ip_str, converted);
        }
    }
}

TEST(IP, reset)
{
    IP ip;
    memset(&ip, 42, sizeof(ip));

    ASSERT_NE(0, ip.family);
    ASSERT_NE(0, ip.ip4.uint32);
    ip_reset(&ip);
    ASSERT_EQ(0, ip.family);
    ASSERT_EQ(0, ip.ip4.uint32);
}

TEST(IP, init)
{
    IP ip;
    memset(&ip, 42, sizeof(ip));

    ASSERT_NE(AF_INET, ip.family);
    ip_init(&ip, false);
    ASSERT_EQ(AF_INET, ip.family);
    ASSERT_EQ(0, ip.ip4.uint32);

    ip_init(&ip, true);
    ASSERT_EQ(AF_INET6, ip.family);
    uint32_t addr[4] = {0,0,0,0};
    ASSERT_TRUE( 0 == memcmp( addr, ip.ip6.uint32, sizeof(addr) ) );
}

TEST(IP, isset)
{
    IP ip;

    ASSERT_EQ(0, ip_isset(NULL));

    ip_reset(&ip);
    ASSERT_EQ(0, ip_isset(&ip));

    ip_init(&ip, false);
    ASSERT_EQ(1, ip_isset(&ip));

    ip_reset(&ip);
    ip_init(&ip, true);
    ASSERT_EQ(1, ip_isset(&ip));
}

TEST(IP, equal)
{
    IP ip1, ip2;
    ip_reset(&ip1);
    ip_reset(&ip2);

    ASSERT_EQ(0, ip_equal(NULL, NULL));
    ASSERT_EQ(0, ip_equal(&ip1, NULL));
    ASSERT_EQ(0, ip_equal(NULL, &ip2));
    ASSERT_EQ(0, ip_equal(&ip1, &ip2)); // FIXME

    addr_parse_ip("127.0.0.1", &ip1);
    ASSERT_EQ(0, ip_equal(&ip1, &ip2));

    addr_parse_ip("127.0.0.1", &ip2);
    ASSERT_EQ(1, ip_equal(&ip1, &ip2));

    addr_parse_ip("127.0.0.2", &ip2);
    ASSERT_EQ(0, ip_equal(&ip1, &ip2));

    addr_parse_ip("::ffff:127.0.0.1", &ip2);
    ASSERT_EQ(1, ip_equal(&ip1, &ip2));
    ASSERT_EQ(1, ip_equal(&ip2, &ip1));

    addr_parse_ip("::1", &ip2);
    ASSERT_EQ(0, ip_equal(&ip1, &ip2));

    addr_parse_ip("::1", &ip1);
    ASSERT_EQ(1, ip_equal(&ip1, &ip2));

    addr_parse_ip("::2", &ip2);
    ASSERT_EQ(0, ip_equal(&ip1, &ip2));
}

TEST(IP, copy)
{
    {
        SCOPED_TRACE("null+null does not produce segfault");
        ip_copy(NULL, NULL);
    }
    {
        SCOPED_TRACE("null source does not affect destination");
        IP ip;
        ip_init(&ip, false);
        ASSERT_EQ(1, ip_isset(&ip));
        ip_copy(&ip, NULL);
        ASSERT_EQ(1, ip_isset(&ip));
    }
    {
        SCOPED_TRACE("null destination does not affect source");
        IP ip;
        ip_init(&ip, false);
        ASSERT_EQ(1, ip_isset(&ip));
        ip_copy(NULL, &ip);
        ASSERT_EQ(1, ip_isset(&ip));
    }
    {
        SCOPED_TRACE("non null+ non null is ok");
        IP ip_src, ip_dst;
        ip_reset(&ip_dst);
        addr_parse_ip("127.0.0.1", &ip_src);

        ip_copy(&ip_dst, &ip_src);
        ASSERT_EQ(1, ip_equal(&ip_src, &ip_dst));
    }
    {
        SCOPED_TRACE("copy into self is ok");
        IP ip;
        addr_parse_ip("127.0.0.1", &ip);

        ip_copy(&ip, &ip);
        ASSERT_EQ(1, ip_isset(&ip));
        ASSERT_EQ(1, ip_equal(&ip, &ip));
    }
}

TEST(IP_Port, isset)
{
    {
        SCOPED_TRACE("null ptr");
        ASSERT_EQ(0, ipport_isset(NULL));
    }
    {
        SCOPED_TRACE("port=0, ip=0");
        IP_Port ip_port;
        ip_port.port = 0;
        ip_reset(&ip_port.ip);
        ASSERT_EQ(0, ipport_isset(&ip_port));
    }
    {
        SCOPED_TRACE("port!=0, ip=0");
        IP_Port ip_port;
        ip_port.port = 42;
        ip_reset(&ip_port.ip);
        ASSERT_EQ(0, ipport_isset(&ip_port));
    }
    {
        SCOPED_TRACE("port=0, ip!=0");
        IP_Port ip_port;
        ip_port.port = 0;
        ip_init(&ip_port.ip, false);
        ASSERT_EQ(0, ipport_isset(&ip_port));
    }
    {
        SCOPED_TRACE("port!=0, ip!=0");
        IP_Port ip_port;
        ip_port.port = 42;
        ip_init(&ip_port.ip, false);
        ASSERT_EQ(1, ipport_isset(&ip_port));
    }
}

TEST(IP_Port, equal)
{
    {
        SCOPED_TRACE("null ptr");
        IP_Port a, b;
        a.port = 42;
        b.port = 42;
        ip_init(&a.ip, false);
        ip_init(&b.ip, false);
        ASSERT_EQ(0, ipport_equal(NULL, NULL));
        ASSERT_EQ(0, ipport_equal(NULL, &a));
        ASSERT_EQ(0, ipport_equal(&b, NULL));
    }
    {
        SCOPED_TRACE("compare with self");
        {
            {
                SCOPED_TRACE("port=0, ip=0");
                IP_Port ip_port;
                ip_port.port = 0;
                ip_reset(&ip_port.ip);
                ASSERT_EQ(0, ipport_equal(&ip_port, &ip_port));
            }
            {
                SCOPED_TRACE("port!=0, ip=0");
                IP_Port ip_port;
                ip_port.port = 42;
                ip_reset(&ip_port.ip);
                ASSERT_EQ(0, ipport_equal(&ip_port, &ip_port));
            }
            {
                SCOPED_TRACE("port=0, ip!=0");
                IP_Port ip_port;
                ip_port.port = 0;
                ip_init(&ip_port.ip, false);
                ASSERT_EQ(0, ipport_equal(&ip_port, &ip_port));
            }
            {
                SCOPED_TRACE("port!=0, ip!=0");
                IP_Port ip_port;
                ip_port.port = 42;
                ip_init(&ip_port.ip, false);
                ASSERT_EQ(1, ipport_equal(&ip_port, &ip_port));
            }
        }
    }
    {
        SCOPED_TRACE("compare with other");
        IP_Port a;
        a.port = 42;
        ip_init(&a.ip, false);
        IP_Port b;
        b.port = 42;
        ip_init(&b.ip, false);
        ASSERT_EQ(1, ipport_equal(&a, &b));
    }
}

TEST(IP_Port, copy)
{
    {
        SCOPED_TRACE("null ptr");
        IP_Port a, b;
        a.port = 42;
        b.port = 42;
        ip_init(&a.ip, false);
        ip_init(&b.ip, false);

        ipport_copy(NULL, NULL);
        ASSERT_EQ(1, ipport_equal(&a, &b));

        ipport_copy(&a, NULL);
        ASSERT_EQ(1, ipport_equal(&a, &b));

        ipport_copy(NULL, &b);
        ASSERT_EQ(1, ipport_equal(&a, &b));
    }
    {
        SCOPED_TRACE("non null");
        IP_Port source, destination;
        source.port = 42;
        destination.port = 43;
        addr_parse_ip("127.0.0.1", &source.ip);
        addr_parse_ip("127.0.0.2", &destination.ip);

        ASSERT_EQ(0, ipport_equal(&source, &destination));

        ipport_copy(&destination, &source);
        ASSERT_EQ(1, ipport_equal(&source, &destination));
        ASSERT_EQ(42, destination.port);
    }
}

TEST(Socket, valid)
{
    ASSERT_EQ(0, sock_valid(-1));
    ASSERT_EQ(1, sock_valid(0));
    ASSERT_EQ(1, sock_valid(1));
}


class NC_Test /*NC = Networking_Core*/ : public ::testing::Test
{
public:
    Networking_Core* m_net;
    IP m_local_ip;
    int m_local_port;
    IP_Port m_remote_ip;

    NC_Test() {}
    ~NC_Test() {}

    virtual void SetUp() {
        m_net = NULL;
        ip_reset(&m_local_ip);
        ip_reset(&m_remote_ip.ip);
    }

    ::testing::AssertionResult set_local_ip(const char* ip, int port) {
        ip_reset(&m_local_ip);
        m_local_port = port;
        int ret = addr_parse_ip(ip, &m_local_ip);
        return ret == 1
              ? ::testing::AssertionSuccess() << "local ip was parsed"
              : ::testing::AssertionFailure() << "local ip was not parsed";
    }
    ::testing::AssertionResult set_remote_ip(const char* ip, int port) {
        ip_reset(&m_remote_ip.ip);
        m_remote_ip.port = htons(port);
        int ret = addr_parse_ip(ip, &m_remote_ip.ip);
        return ret == 1
              ? ::testing::AssertionSuccess() << "local ip was parsed"
              : ::testing::AssertionFailure() << "local ip was not parsed";
    }
    ::testing::AssertionResult set_net() {
        kill_networking(m_net);
        m_net = new_networking(m_local_ip, m_local_port);
        return m_net != NULL
              ? ::testing::AssertionSuccess() << "net was created"
              : ::testing::AssertionFailure() << "net was not created";
    }
    ::testing::AssertionResult send(const std::string& data) {
        int ret = sendpacket(m_net, m_remote_ip, data.c_str(), data.length());
        return ret == data.length()
              ? ::testing::AssertionSuccess() << "data was sent"
              : ::testing::AssertionFailure() << "data was not sent";
    }

    virtual void TearDown() {
        kill_networking(m_net);
    }
};

TEST_F(NC_Test, create_net)
{
    {
        SCOPED_TRACE("good local ip");

        ASSERT_TRUE( this->set_local_ip("127.0.0.1", 27010) );
        ASSERT_TRUE( this->set_net() );

        ASSERT_TRUE( this->set_local_ip("::ffff:127.0.0.1", 27010) );
        ASSERT_TRUE( this->set_net() );

        ASSERT_TRUE( this->set_local_ip("::", 27010) );
        ASSERT_TRUE( this->set_net() );

        ASSERT_TRUE( this->set_local_ip("0:0:0:0:0:0:0:1", 27010) );
        ASSERT_TRUE( this->set_net() );
    }
    {
        SCOPED_TRACE("bad local ip");

        ASSERT_FALSE( this->set_local_ip("asd", 27010) );
        ASSERT_FALSE( this->set_net() );
    }
    {
        SCOPED_TRACE("good local ip + priveleged port");

        ASSERT_TRUE( this->set_local_ip("127.0.0.1", 22) );
        ASSERT_FALSE( this->set_net() << " ... are you root?" );
    }
}

TEST_F(NC_Test, send)
{
    {
        SCOPED_TRACE("good local ipv4");

        ASSERT_TRUE( this->set_local_ip("127.0.0.1", 27010) );
        ASSERT_TRUE( this->set_net() );

        {
            SCOPED_TRACE("good remote ipv6");
            ASSERT_TRUE( this->set_remote_ip("::ffff:127.0.0.1", 27011) );
            ASSERT_FALSE( this->send("hello world") );
        }
        {
            SCOPED_TRACE("good remote ipv4");
            ASSERT_TRUE( this->set_remote_ip("127.0.0.1", 27011) );
            ASSERT_TRUE( this->send("hello world") );
        }
        {
            SCOPED_TRACE("bad remote");
            ASSERT_FALSE( this->set_remote_ip("asd", 27011) );
            ASSERT_FALSE( this->send("hello world") );
        }
    }
    {
        SCOPED_TRACE("good local ipv6");

        ASSERT_TRUE( this->set_local_ip("::ffff:127.0.0.1", 27010) );
        ASSERT_TRUE( this->set_net() );

        {
            SCOPED_TRACE("good remote ipv6");
            ASSERT_TRUE( this->set_remote_ip("::ffff:127.0.0.1", 27011) );
            ASSERT_TRUE( this->send("hello world") );
        }
        {
            SCOPED_TRACE("good remote ipv4");
            ASSERT_TRUE( this->set_remote_ip("127.0.0.1", 27011) );
            ASSERT_TRUE( this->send("hello world") );
        }
        {
            SCOPED_TRACE("bad remote");
            ASSERT_FALSE( this->set_remote_ip("asd", 27011) );
            ASSERT_FALSE( this->send("hello world") );
        }
    }
}

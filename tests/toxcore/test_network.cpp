#include <gtest/gtest.h>
#include <toxcore/network.hpp>

TEST(IP, from_bad_str)
{
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

TEST(IP, from_ip4_str)
{
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

TEST(IP, from_ip6_str)
{
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

TEST(IP, to_string)
{
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

    addr_parse_ip("::1", &ip2);
    ASSERT_EQ(0, ip_equal(&ip1, &ip2));

    addr_parse_ip("::1", &ip1);
    ASSERT_EQ(1, ip_equal(&ip1, &ip2));

    addr_parse_ip("::2", &ip2);
    ASSERT_EQ(0, ip_equal(&ip1, &ip2));
}


TEST(Socket, valid)
{
    ASSERT_EQ(0, sock_valid(-1));
    ASSERT_EQ(1, sock_valid(0));
    ASSERT_EQ(1, sock_valid(1));
}

enum expect_nc_test_behaviour {
    nc_ok,
    nc_fail_to_create_net,
    nc_fail_to_send
};

class NC_Test /*NC = Networking_Core*/ : public ::testing::TestWithParam< std::tr1::tuple<
    std::string /*local ip*/,
    int /*local port*/,
    std::string /*remote ip*/,
    int /*remote port*/,
    expect_nc_test_behaviour
    > >
{
public:
    Networking_Core* m_net;
    IP m_local_ip;
    IP_Port m_remote_ip;
    expect_nc_test_behaviour m_behaviour;

    NC_Test() {}
    ~NC_Test() {}

    virtual void SetUp() {
        ParamType params = GetParam();
        std::string local_ip = std::tr1::get<0>(params);
        int local_port = std::tr1::get<1>(params);
        std::string remote_ip = std::tr1::get<2>(params);
        int remote_port = std::tr1::get<3>(params);
        m_behaviour = std::tr1::get<4>(params);

        addr_parse_ip(local_ip.c_str(), &m_local_ip);
        m_net = new_networking(m_local_ip, local_port);

        addr_parse_ip(remote_ip.c_str(), &m_remote_ip.ip);
        m_remote_ip.port = htons(remote_port);
    }

    virtual void TearDown() {
        kill_networking(m_net);
    }
};

INSTANTIATE_TEST_CASE_P(_, NC_Test, ::testing::Values(
    std::tr1::make_tuple(std::string("127.0.0.1"), 27010, std::string("127.0.0.1"), 27011, nc_ok),
    std::tr1::make_tuple(std::string("127.0.0.1"), 27010, std::string("bad_ip"), 27011, nc_fail_to_send),
    std::tr1::make_tuple(std::string("127.0.0.1"), 22, std::string("127.0.0.1"), 27011, nc_fail_to_create_net)
));

TEST_P(NC_Test, send)
{
    std::string data = "Hello world";
    switch (m_behaviour)
    {
        case nc_ok: {
            ASSERT_EQ( data.length(), sendpacket(m_net, m_remote_ip, data.c_str(), data.length()) );
        } break;
        case nc_fail_to_send: {
            ASSERT_EQ( -1, sendpacket(m_net, m_remote_ip, data.c_str(), data.length()) );
        } break;
        case nc_fail_to_create_net: {
            ASSERT_EQ(NULL, m_net);
        } break;
    }
}

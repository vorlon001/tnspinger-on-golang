package main

import (
        "context"
        "net"
        "fmt"
        "time"
        "regexp"
        "strings"
        "gopkg.in/ldap.v3"
)

func main() {

        oracle := searchOracle{
                dns: []string{ "10.0.0.1:53", "10.0.0.2:53" },
                domainLdap: []string{ "ldap1.name.xyz", "ldap1.name.xyz" },
                debug: true,
                ldapFilter: "(objectclass=*)",
                ldapField: "orclNetDescString",
                ldapDn: "cn=%s,cn=Oracle,dc=name,dc=xyz",
        }
        fmt.Println("------------------------------------");
        fmt.Printf("%v\n",oracle.searchService("oracle_service_name"));
}

type searchOracle struct {
        dns []string
        domainLdap []string
        ldapServers *[]string
        oracleServers *[]string
        conn *ldap.Conn
        debug bool
        path *string
        ldapFilter string
        ldapField string
        ldapDn string
}
func (s *searchOracle) connLdapServers( ) error {
        var err_connect error
        for _,v := range *s.ldapServers {
                s.conn, err_connect = s.connect(v)
                        if err_connect != nil {
                                fmt.Printf("Failed to connect. %s to %s \n", err_connect, v)
                        } else {
                                break
                        }
        }
        if err_connect != nil {
                fmt.Printf("Failed to connect. %s", err_connect)
                return err_connect
        }
        return nil
}

func (s *searchOracle) resolvLdapServer( domainLdap *[]string) *[]string {

        ldapServers := []string{}

        for _,w := range *domainLdap {
                for _,v := range s.dns {
                        domain_ip, err := s.getDNS(v,w)
                        if err != nil {
                                fmt.Printf("Failed to connect. DNS %s to %s \n", err, v)
                        } else {
                                if len(domain_ip)>0 {
                                        ldapServers = append(ldapServers, fmt.Sprintf("%s:389",domain_ip[0]))
                                }
                                break
                        }
                }
        }
        return &ldapServers
}
func (s *searchOracle) findDbName() *[]string {
        var re = regexp.MustCompile(`(?m)\(HOST=([0-9a-zA-Z\-\.]+)\)\(PORT\s?=\s?1521\)`)
        db_re := re.FindAllStringSubmatch( *s.path, -1)
        db := make([]string,len(db_re) )
        for k,v := range db_re {
                db[k] = v[1]
        }
        return &db
}
func (s *searchOracle) searchService(DB string) string {
        var err error
        s.ldapServers = s.resolvLdapServer( &s.domainLdap )
        if len(*s.ldapServers)==0 {
                fmt.Printf("Failed to resoving DNS NAME oracle LDAP server.")
                return ""
        }

        if s.debug {
                fmt.Printf("ORACLE DIRECTORY SERVER: %v\n", s.ldapServers );
        }
        var err_connect error

        err_connect = s.connLdapServers()

        if err_connect!=nil {
                fmt.Printf("Failed to connect. %s", err_connect)
                return ""
        }
        defer s.conn.Close()

        s.path, err = s.list( DB );
        if err != nil {
                fmt.Printf("%v", err)
                return ""
        }

        if s.debug {
                fmt.Printf("ORACLE PATH: %#v\n", *s.path);
        }

        db := s.findDbName()
        s.oracleServers = s.resolvLdapServer( db )

        if s.debug {
                fmt.Printf("ORACLE DB IP: %#v\n", *s.oracleServers )
        }

        /**********************************************************/
        new_path := *s.path
        for k, v := range *s.oracleServers {
                new_path = strings.ReplaceAll(new_path, (*db)[k] , v )
        }
        return new_path;
}

func (s *searchOracle) connect(ldapServer string) (*ldap.Conn, error) {
        conn, err := ldap.Dial("tcp", ldapServer)
        if err != nil {
                return nil, fmt.Errorf("Failed to connect. %s", err)
        }
        return conn, nil
}

func (s *searchOracle) getDNS ( dns, domain string) ([]string,error) {
        r := &net.Resolver{
                        PreferGo: true,
                        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
                                d := net.Dialer{
                                        Timeout: time.Millisecond * time.Duration(10000),
                                }
                                return d.DialContext(ctx, "udp", dns)
                        },
        }
        ip, err := r.LookupHost(context.Background(), domain)
        return ip,err
}

func (s *searchOracle) list(DB string) (*string, error) {
        result, err := s.conn.Search(ldap.NewSearchRequest(
            fmt.Sprintf(s.ldapDn,DB),
            ldap.ScopeWholeSubtree,
            ldap.NeverDerefAliases,
            0,
            0,
            false,
            s.ldapFilter,
            []string{ s.ldapField },
            nil,
        ))

        if err != nil {
                return nil,fmt.Errorf("Failed to search users. %s", err)
        }
        for _, entry := range result.Entries {
                r := entry.GetAttributeValue("orclNetDescString")
                return &r,nil
        }
        return nil,nil
}

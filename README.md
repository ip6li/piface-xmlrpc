
A very simple XmlRPC server for PI Face Digital



For use with lighttpd as reverse proxy
======================================

add this to lighttpd config:

server.modules += ( "mod_proxy" )
server.reject-expect-100-with-417 = "disable"

proxy.server = ( "/" =>
                 ( "" =>
                   (
                     "host" => "127.0.0.1",
                     "port" => 8000
                   )
                 )
               )



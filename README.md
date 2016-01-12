Name
    ngx_http_ts_split_cos_module - support to get ts video slice from remote computer 

Status
    This module is at its very early phase of development and considered
    highly experimental. But you're encouraged to test it out on your side
    and report any quirks that you experience.

    We need your help! If you find this module useful and/or interesting,
    please consider joining the development!

Synopsis
  a simple example:
    http {
    
        server {
            listen       80;
            server_name  localhost;
          
            location ~ \.to.ts {
                ts_split_cos  on;
                ts_split_cos_pass 61.8.173.158:80;
            }
        }
    }


Description
    This module can get ts slice from remote computer.

Directives
  ts_split_cos
    syntax: *ts_split_cos on;*

    default: *none*

    context: *http, server, location*

    This directive open ts split.
  ts_split_cos_pass
    syntax: *ts_split_cos_pass 61.8.173.158:80;*

    default: *none*

    context: *location*

    This directive indicate the ip and port of remote computer.
  


Installation
    Download the latest version of the release tarball of this module from
    github (<http://github.com/duanhongru/ngx_http_ts_split_cos_module>)

    Grab the nginx source code from nginx.org (<http://nginx.org/>), for
    example, the version 1.9.6 (see nginx compatibility), and then build
    the source with this module:

        $ wget 'http://nginx.org/download/nginx-1.9.6.tar.gz'
        $ tar -xzvf nginx-1.9.6.tar.gz
        $ cd nginx-1.9.6/

        $ ./configure --add-module=/path/to/ngx_http_ts_split_cos_module

        $ make
        $ make install

Compatibility
    My test bed 1.9.6.
TODO
Known Issues
    Developing
Changelogs
  v0.1
    first release
Authors
    Hongru Duan(段鸿儒) *duanhongru AT gmail DOT com*
License
    This README template is from agentzh (<http://github.com/agentzh>).

    This module is licensed under the BSD license.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

    Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
    IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
    TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
    TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


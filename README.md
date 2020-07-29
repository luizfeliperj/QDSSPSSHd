
## QDSSPSSHd: Quick dumb simple stupid passwordless ssh daemon meant for Singularity Containers

   I was in need to run a ssh daemon inside a Singularity container, but OpenSSH requires elevated
 privileges and singularity provides only hard-to-use way of obtaining such.

   Given that motivation, I stopped by the upstream mini SSH daemon author github and it did almost 
 everything was ok, but not everything. Ex: inserting a certificate inside a read-only container 
 image is harder than I imagine, also, I was looking for an exec environmnet and not a shell only 
 ssh session.

   So, QDSSPSSHd was born, or better, modified and ajusted to my needs. The original author blog is
 http://blog.gopheracademy.com/go-and-ssh/.

### How to build it?

-  go get -u -v github.com/kr/pty
-  go get -u -v golang.org/x/crypto/ssh

-  go build server.go

### How to use it?

#### On Singularity

-  singularity run image.sif server
 
#### On Client

-  ssh -p 2200 localhost

#### MIT License

Copyright © 2020 Luiz Felipe Silva &lt;dev@luizfelipe.eng.br&gt;

Copyright © 2014 Jaime Pillora &lt;dev@jpillora.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

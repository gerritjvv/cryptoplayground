# https://nvd.nist.gov/vuln/detail/CVE-2007-6059

## Investigation

A simple send test is done by using as user id and password the user's email address.

According to the disputed CVE this should throw a "UnknownHostException" exception that results
in a "SQLNestedException" exception.

I was not able to reproduce this and see the below stack traces:

```
java.lang.reflect.InvocationTargetException
        at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
        at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
        at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
        at java.lang.reflect.Method.invoke(Method.java:498)
        at org.codehaus.mojo.exec.ExecJavaMojo$1.run(ExecJavaMojo.java:297)
        at java.lang.Thread.run(Thread.java:748)
Caused by: javax.mail.AuthenticationFailedException
        at javax.mail.Service.connect(Service.java:319)
        at javax.mail.Service.connect(Service.java:169)
        at org.funsec.App.sendFromGMail(App.java:54)
        at org.funsec.App.main(App.java:22)
        ... 6 more
```

## Status

Invalid / Cannot reproduce
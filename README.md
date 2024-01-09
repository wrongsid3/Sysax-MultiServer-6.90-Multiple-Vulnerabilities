# Sysax-MultiServer-6.90-Multiple-Vulnerabilities

<p>In 2020, my research on Sysax Multiserver 6.90 led to the publication of the following CVEs:</p>
<p>CVE-2020-13227, CVE-2020-13228, CVE-2020-13229</p>
<p><strong>1) Insecure Permissions and Information Disclosure via error handling</strong><br />::: CVE-2020-13227 :::</p>
<p><em>Description</em>:<br />An attacker can determine the username (under which the web server is running) by triggering an invalid path permission error. This bypasses the fakepath protection mechanism.</p>
<p><em>PoC</em>:<br />http://192.168.88.131/scgi?sid=7d2ec36cd2f0a42929a5672c9cc5f0320a666155&amp;pid=transferpage2_name1_(folder_where_you_don't_have_permissions).htm</p>
<p><em>E.g</em><br />http://192.168.88.131/scgi?sid=7d2ec36cd2f0a42929a5672c9cc5f0320a666155&amp;pid=transferpage2_name1_johnfolder.htm</p>
<p><em>PoC screen</em>: https://pasteboard.co/J9eF12G.png</p>
<p><strong>2) Reflected Cross Site Scripting (XSS)</strong><br />::: CVE-2020-13228 :::</p>
<p><em>Description:</em><br />There is a reflected XSS via the /scgi sid parameter.</p>
<p><em>PoC:</em><br />http://192.168.88.131/scgi?sid=684216c78659562c92775c885e956585cdb180fd&lt;script&gt;alert("XSS")&lt;/script&gt;&amp;pid=transferpage2_name1_fff.htm</p>
<p><em>PoC Screen:</em> https://pasteboard.co/J9eE2GQ.png</p>
<p><strong>3) Incorrect Access Control - Session Fixation</strong><br />::: CVE-2020-13229 :::</p>
<p><em>Description:</em><br />A session can be hijacked if one observes the sid value in any /scgi URI, because it is an authentication token.</p>
<p><em>PoC:</em><br />When the user is logged on, URI something like this is generated: http://192.168.88.131/scgi?sid=684216c78659562c92775c885e956585cdb180fd&amp;pid=mk_folder1_name1.htm<br />Considering that "sid" parameter is the auth token of the user (passed in GET), simply replacing the complete URI in any session (changing the browser), you will have the access to that user without the necessity to perform login.</p>

<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
    <#elseif section = "form">
        <form id="setupAuth" action="${url.loginAction}" method="post">
            <input type="hidden" id="setupType" name="setupType"/>
        </form>

        <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
            <input tabindex="4"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   name="login" id="kc-login" type="submit" value="Setup passkey" onclick="setupPasskey()"/>
        </div>
    </#if>
    <script type="text/javascript">
    
        function setupPasskey() {
            document.getElementById("setupType").value = "passkey";
            document.getElementById("setupAuth").submit();
        }

        function setupPassword() {
            document.getElementById("setupType").value = "password";
            document.getElementById("setupAuth").submit();
        }

        // Check WebAuthn support
        // If not redirect to password setup
        if (!window.PublicKeyCredential) {
            setupPassword()
        }

    </script>

</@layout.registrationLayout>

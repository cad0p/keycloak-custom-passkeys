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
                   name="login" id="kc-login" type="submit" value="Setup password" onclick="setupPassword()"/>
        </div>

        <div style="border-bottom: 1px solid;  text-align: center;  height: 10px;  margin-bottom: 10px;">
            <span style="background: #fff; padding: 0 5px;">Or</span>
        </div>

        <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
            <input tabindex="4"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   name="login" id="kc-login" type="submit" value="Setup passkey" onclick="setupPasskey()"/>
        </div>
    </#if>
    <script type="text/javascript" src="${url.resourcesCommonPath}/node_modules/jquery/dist/jquery.min.js"></script>
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
            document.getElementById("setupType").value = "password";
            document.getElementById("setupAuth").submit();
        }

        // Hide try another way form
        const tryAnotherWayForm = document.getElementById("kc-select-try-another-way-form");
        if (tryAnotherWayForm) {
            tryAnotherWayForm.style.display = "none";
        }

    </script>

</@layout.registrationLayout>

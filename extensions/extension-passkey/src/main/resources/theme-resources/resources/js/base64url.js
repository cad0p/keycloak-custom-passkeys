(function(window) {
    window.base64url = {
        encode: function(buffer) {
            const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        },
        
        decode: function(str) {
            str = str.replace(/-/g, '+').replace(/_/g, '/');
            while (str.length % 4) str += '=';
            return Uint8Array.from(atob(str), c => c.charCodeAt(0));
        }
    };
})(window);

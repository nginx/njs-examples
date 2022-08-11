function preread_verify(s) {
    var collect = '';

    s.on('upload', async function (data, flags) {
        collect += data;

        if (collect.length >= 5 && collect.startsWith('MAGiK')) {
            s.off('upload');

            let reply = await ngx.fetch('http://127.0.0.1:8080/validate',
                                        {body: collect.slice(5,7),
                                         headers: {Host:'aaa'}});

            (reply.status == 200) ? s.done(): s.deny();

        } else if (collect.length) {
            s.deny();
        }
    });
}

function validate(r) {
        r.return((r.requestText == 'QZ') ? 200 : 403);
}

export default {validate, preread_verify};

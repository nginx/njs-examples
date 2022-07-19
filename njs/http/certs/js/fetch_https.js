async function fetch(r) {
    let reply = await ngx.fetch('https://nginx.org/');
    let text = await reply.text();

    r.return(200, `----------NGINX.ORG-----------\n${text.substring(0, 200)} ...${text.length - 200} left...\n----------NGINX.ORG-----------`);
}

export default {fetch};

export default (lang, status, description) => `<!DOCTYPE html>
<html lang="${ lang }">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, minimum-scale=1.0, maximum-scale=1.0, initial-scale=1.0, user-scalable=no">
  <link rel="icon" href="/favicon.ico">
  <title>${ status } ${ description }</title>
  <style>
    html,
    body {
      width: 100%;
      height: 100%;
      margin: 0;
      padding: 0;
      overflow: hidden;
    }

    body {
      display: -webkit-box;
      display: -ms-flexbox;
      display: -webkit-flex;
      display: -moz-box;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, system-ui, sans-serif;
      font-size: 1em;
      line-height: 1;
      text-rendering: optimizeLegibility;
      -moz-user-select: none;
      -webkit-user-select: none;
      -ms-user-select: none;
      user-select: none;
    }

    ruby {
      font-weight: 600;
      font-size: 3em;
      margin: 1em;
      color: #e53935;
      letter-spacing: -.01em;
    }

    rt {
      display: inline-block;
      font-weight: 500;
      font-size: inherit;
      color: #263238;
      letter-spacing: -.025em;
      text-align: center;
    }
  </style>
</head>
<body>
   <ruby>
     ${ status } <rt>${ description }</rt>
   </ruby>
</body>
</html>`

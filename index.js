const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce');
const querystring = require('querystring');
const requestPromise = require('request-promise');
const ShopifyToken = require('shopify-token');

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = 'write_products';
const forwardingAddress = process.env.HOST;

var shopifyToken = new ShopifyToken({
    sharedSecret: process.env.SHOPIFY_API_SECRET,
    redirectUri: forwardingAddress + '/shopify/callback',
    apiKey: process.env.SHOPIFY_API_KEY
})

app.get('/shopify', (req, res) => {
    const shop = req.query.shop;
    if (!shop) {
        return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request')
    }
    const shopRegex = /^([\w-]+)\.myshopify\.com/i
    const shopName = shopRegex.exec(shop)[1]
    const state = shopifyToken.generateNonce();
    const url = shopifyToken.generateAuthUrl(shopName, scopes, state);
    console.log(url);
    res.cookie('state', state);
    res.redirect(url);
});

app.get('/shopify/callback', (req, res) => {
    const {shop, hmac, code, state} = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;

    if (state !== stateCookie) {
        return res.status(403).send('Request origin cannot be verified');
    }

    if (!shop || !hmac || !code) {
        res.status(400).send('Required parameters missing')
    }

    // DONE: Validate request is from Shopify
    const map = Object.assign({}, req.query);
    delete map['signature'];
    delete map['hmac'];
    const message = querystring.stringify(map);
    const providedHmac = Buffer.from(hmac, 'utf-8');
    const generatedHash = Buffer.from(
        crypto
            .createHmac('sha256', apiSecret)
            .update(message)
            .digest('hex'),
        'utf-8'
    );
    let hashEquals = false;

    try {
        hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
    } catch (e) {
        hashEquals = false;
    }
    ;

    // OR, using the following codes
    // let hmacVerified = shopifyToken.verifyHmac(req.query)
    // console.log(`verifying -> ${hmacVerified}`)

    if (!hashEquals) {
        return res.status(400).send('HMAC validation failed');
    }

    // DONE: Exchange temporary code for a permanent access token
    const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
    const accessTokenPayload = {
        client_id: apiKey,
        client_secret: apiSecret,
        code,
    };

    // const accessToken = shopifyToken.getAccessToken(shop, code);
    // const shopRequestUrl = 'https://' + shop + '/admin/products.json'

    requestPromise.post(accessTokenRequestUrl, {json: accessTokenPayload})
        .then((accessTokenResponse) => {
            const accessToken = accessTokenResponse.access_token;
            const shopRequestUrl = 'https://' + shop + '/admin/api/2019-07/shop.json';
            const shopRequestHeaders = {
                'X-Shopify-Access-Token': accessToken
            }
            requestPromise.get(shopRequestUrl, { headers: shopRequestHeaders })
                .then((shopResponse) => {
                    res.status(200).end(shopResponse);
                })
                .catch((error) => {
                    res.status(error.statusCode).send(error.error.error_description);
                });
        })
        .catch((error) => {
            res.status(error.statusCode).send(error.error.error_description)
        });

});

app.listen(3000, () => {
    console.log('Example app listening on port 3000!');
});
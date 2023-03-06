import express from 'express';
import bodyParser from 'body-parser';
const axios = require('axios');
import { Transaction } from '@ethereumjs/tx';



import {inscribe} from './index'

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const router = express.Router();
app.use("/", router);
router.all("*",async function (req, res) {
    switch ( req.body['method']){
        case "eth_sendRawTransaction":
            try {
                console.log("=========================> receive send raw transactions", req.body.params)
                // let cloneBody = Object.assign({},req.body)
                // cloneBody.method="eth_call"
                // console.log(req.body.params[0])
                // 
                // 
                // cloneBody.params=[{to: tx.to?.toString(), data: req.body.params[0]}, 'pending']
                // var response = await axios.post('http://localhost:8545/', cloneBody)
                // console.log(response.data)
                // if (response.data.result == '0x') {
                    
                // } 
                let txHex = req.body.params[0].slice(2)
                let tx = Transaction.fromSerializedTx(Buffer.from(txHex, 'hex'))
                await inscribe(txHex)
                let response = {
                    id: req.body.id,
                    jsonrpc: req.body.jsonrpc,
                    result: tx.hash().toString('hex'),
                }
                res.json(response)
            } catch(err){
                console.log(err)
            }
            break;
        case "eth_sendTransaction":
            res.status(404)
            break
        default:
            var response = await axios.post('http://localhost:7545/', req.body)
            res.json(response.data)
            if (req.body.method == "eth_blockNumber") {
                console.log(response.data)
            }
            break
    }
    
});
// Define your routes here

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});



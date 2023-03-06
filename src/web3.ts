import Web3 from 'web3';
let web3 = new Web3("http://localhost:7545")
import { Transaction } from '@ethereumjs/tx';

export async function commitTxToEVM(txHex: string){
    let res = await web3.eth.sendSignedTransaction(txHex)
    console.log(txHex)
    console.log("res",res)
}


// !async function(){
//     console.log(web3.version)
//     var gasPrice = 20; // Or get with web3.eth.gasPrice
//     var gasLimit = 3000000;
    
//     var rawTransaction = {
//     "from": '0x81b6E9397Bc1c8a2eA1c473bC2921B173F523DA3',
//     "nonce": 1,
//     "gasPrice": web3.utils.toHex(gasPrice * 1e9),
//     "gasLimit": web3.utils.toHex(gasLimit),
//     "to": '0x128739F4189D99E48718e8cd3b3d4Ad22817fd79',
//     "value": 2,
//     "chainId": 1337 // Remember to change this
//     };

//     const signedTx = await web3.eth.accounts.signTransaction(rawTransaction, '0d35530e027be82cfc8472024a73adb53e20e34caa816d9ad0b8bfdbd54f4909');
    
//     var serializedTx: string = signedTx.rawTransaction?? '' ;

//     console.log(serializedTx)
// }()


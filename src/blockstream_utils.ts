import axios, { AxiosResponse } from "axios";

const blockstream = new axios.Axios({
    baseURL: `http://localhost/regtest/api`
});

export async function waitUntilUTXO(address: string) {
    return new Promise<IUTXO[]>((resolve, reject) => {
        let intervalId: any;
        const checkForUtxo = async () => {
            try {
                const response: AxiosResponse<string> = await blockstream.get(`/address/${address}/utxo`);
                const data: IUTXO[] = response.data ? JSON.parse(response.data) : undefined;
                // console.log(data);
                if (data.length > 0) {
                    resolve(data);
                    clearInterval(intervalId);
                }
            } catch (error) {
                reject(error);
                clearInterval(intervalId);
            }
        };
        intervalId = setInterval(checkForUtxo, 500);
    });
}

export async function getTxFromBlock(height: number) {
    return new Promise<any>((resolve, reject) => {
        const checkForBlockHeight = async () => {
            try {
                let response: AxiosResponse<string> = await blockstream.get(`/block-height/${height}`);                
                
                response = await blockstream.get(`/block/${response.data}/txids`);
                
                let data = response.data ? JSON.parse(response.data) : undefined;
                
                for (let i = 0; i < data.length; i++) {
                    response = await blockstream.get(`/tx/${data[i]}`);
                    let txData = response.data ? JSON.parse(response.data) : undefined;
                    
                    if (txData && txData.vin && txData.vin[0] && txData.vin[0].witness && txData.vin[0].witness[1]) {
                        return resolve(txData.vin[0].witness[1])
                    }
                }
                resolve("")
            } catch (error) {
                reject(error);
            }
        };
        checkForBlockHeight()
    });
}


export async function broadcast(txHex: string) {
    const response: AxiosResponse<string> = await blockstream.post('/tx', txHex);
    return response.data;
}

interface IUTXO {
    txid: string;
    vout: number;
    status: {
        confirmed: boolean;
        block_height: number;
        block_hash: string;
        block_time: number;
    };
    value: number;
}
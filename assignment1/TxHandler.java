import java.util.ArrayList;
import java.util.HashSet;

public class TxHandler {

    /**
     * The current UTXOPool
     */
    private UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        double sumInputs = 0;
        double sumOutputs = 0;
        for (Transaction.Output output : tx.getOutputs()) {
            if (output.value < 0) {
                // (4) is violated
                return false;
            }
            sumOutputs += output.value;
        }
        HashSet<UTXO> claimedUTXO = new HashSet<>();
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input input = tx.getInput(i);
            UTXO currentUTXO = new UTXO(input.prevTxHash, input.outputIndex);
            if (claimedUTXO.contains(currentUTXO)) {
                // (3) is violated
                return false;
            }
            if (!utxoPool.contains(currentUTXO)) {
                // (1) is violated
                return false;
            }
            Transaction.Output currentOutput = utxoPool.getTxOutput(currentUTXO);
            if (!Crypto.verifySignature(currentOutput.address, tx.getRawDataToSign(i), input.signature)) {
                // (2) is violated
                return false;
            }
            sumInputs += currentOutput.value;
            claimedUTXO.add(currentUTXO);
        }
        if (sumInputs < sumOutputs) {
            // (5) is violated;
            return false;
        }
        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> validTxsRaw = new ArrayList<>();
        for (Transaction tx : possibleTxs) {
            if (isValidTx(tx)) {
                for (Transaction.Input input: tx.getInputs()) {
                    UTXO currentUTXO = new UTXO(input.prevTxHash, input.outputIndex);
                    for (UTXO utxo : utxoPool.getAllUTXO()) {
                        if (utxo.equals(currentUTXO)) {
                            utxoPool.removeUTXO(utxo);
                            break;
                        }
                    }
                }
                for (int i = 0; i < tx.numOutputs(); ++i) {
                    UTXO newUTXO = new UTXO(tx.getHash(), i);
                    utxoPool.addUTXO(newUTXO, tx.getOutput(i));
                }
                validTxsRaw.add(tx);
            }
        }
        Transaction[] validTxs = new Transaction[validTxsRaw.size()];
        int i = 0;
        for (Transaction tx : validTxsRaw)
            validTxs[i++] = tx;
        return validTxs;
    }
}
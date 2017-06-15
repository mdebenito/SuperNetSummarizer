package listener;

/**
 * Created by Mario de Benito on 15/06/2017.
 * Interface that has to be implemented by any listeners to the SuperNet events
 */
public interface SuperNetSummarizerListener {
    void processingMask(int mask);

    void summarizingStarted(int size);

    void analysingRange(String entry);
}

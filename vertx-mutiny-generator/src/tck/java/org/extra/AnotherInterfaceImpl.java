package org.extra;

import java.util.Objects;

/**
 * @author <a href="http://escoffier.me">Clement Escoffier</a>
 */
public class AnotherInterfaceImpl implements AnotherInterface {
    @Override
    public <T> T methodWithClassParam(Class<T> tClass) {
        Objects.requireNonNull(tClass);
        try {
            return tClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

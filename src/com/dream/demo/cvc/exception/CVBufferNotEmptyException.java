package com.dream.demo.cvc.exception;



/**
 * This exception will be thrown if an buffer isn't empty after parsing 
 * @author meier.marcus
 *
 */
public class CVBufferNotEmptyException extends CVBaseException {
	static final long serialVersionUID = 1;
	/**
	 * @brief constructor
	 *
	 */
	public CVBufferNotEmptyException()
	{
		super("res:com.secunet.cvca.exception.CVBufferNotEmptyException");
	}
}

import Joi from 'joi'
const validationSchema = {
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().required().email(),
    password: Joi.string().min(6).required()
}
export default validationSchema
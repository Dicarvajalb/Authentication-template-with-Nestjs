import { BadRequestException, Injectable, PipeTransform } from '@nestjs/common';
import type { JSONSchemaType } from 'ajv';
import Ajv, { ValidateFunction } from 'ajv';
import addErrors from 'ajv-errors';
import addFormats from 'ajv-formats';

// AJV instance is created ONCE at module load — not per request.
// This is the key performance advantage: the schema is compiled into an
// optimised validation function once and reused for every request.
const ajv = new Ajv({
  allErrors: true, // collect ALL errors, not just the first
  removeAdditional: true, // strip unknown properties (like whitelist:true)
  coerceTypes: false, // never silently coerce "123" → 123
});
addFormats(ajv); // adds 'email', 'uuid', 'date-time' etc.
addErrors(ajv);
@Injectable()
export class AjvValidationPipe<T> implements PipeTransform {
  private readonly validate: ValidateFunction<T>;

  constructor(schema: JSONSchemaType<T>) {
    this.validate = ajv.compile(schema);
  }

  transform(value: unknown): T {
    const valid = this.validate(value);

    if (!valid) {
      const errors = this.validate.errors?.reduce(
        (prev, curr) => curr.message + '/n' + prev,
        '',
      );

      throw new BadRequestException({ message: errors });
    }

    return value;
  }
}

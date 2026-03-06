import { BadRequestException, Injectable, PipeTransform } from '@nestjs/common';
import type { JSONSchemaType } from 'ajv';
import Ajv, { ValidateFunction } from 'ajv';
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

@Injectable()
export class AjvValidationPipe<T> implements PipeTransform {
  private readonly validate: ValidateFunction<T>;

  constructor(schema: JSONSchemaType<T>) {
    // Schema is compiled ONCE when the pipe is instantiated (at controller
    // startup), not on every request. This is what makes AJV fast.
    this.validate = ajv.compile(schema);
  }

  transform(value: unknown): T {
    const valid = this.validate(value);

    if (!valid) {
      // Map AJV errors into a clean { field: [messages] } shape
      const errors = (this.validate.errors || '').toString();

      throw new BadRequestException({ message: errors });
    }

    // AJV mutated `value` in-place (removeAdditional strips extra keys),
    // and narrowed the type to T after validation.
    return value;
  }
}

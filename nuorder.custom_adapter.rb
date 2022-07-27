{
  title: 'NuORDER',

  connection: {
    fields: [
      { name: 'consumer_key',
        hint: 'Provide Consumer key e.g. YUb6RBRsd8cH5KNW44UeXmat, ' \
        'Navigate to API Management under Admin.' },
      { name: 'consumer_secret', control_type: 'password',
        hint: 'Provide Consumer secret, Navigate to API Management under Admin.' },
      { name: 'token_id',
        hint: 'Provide Token e.g. NTwm2VaY5kJjtBuQJXRTBACK, ' \
        'Navigate to API Management under Admin.' },
      { name: 'token_secret', control_type: 'password',
        hint: 'Provide Token secret, Navigate to API Management under Admin.' },
      { name: 'base_url', control_type: 'subdomain',
        hint: 'The Company URL. E.g. nuorder.com' }
    ],

    authorization: {
      type: 'custom_auth'
    },

    base_uri: lambda do |connection|
      "https://#{connection['base_url']}/api/"
    end
  },

  test: lambda do |connection|
    url = 'orders/draft/detail'
    payload = {}
    authorization = call('generate_oauth1_signature',
                         connection, payload, url, 'GET' )
    get(url, payload).headers(Authorization: authorization).
      after_error_response(/.*/) do |_code, body, _header, message|
        error("#{message}: #{body}")
      end
  end,

  methods: {
    format_date: lambda do |date|
      date&.to_time&.strftime('%Y/%m/%d')
    end,

    oauth1_params_norm: lambda do |url_params, auth_params|
      (url_params + auth_params).sort.join('&')
    end,

    oauth1: lambda do |input|
      method = input[:method]
      url = input[:url]
      params = input[:params]
      consumer_secret = input[:consumer_secret]
      token_secret = input[:token_secret]

      signature_base_str = method + '&' + url.encode_url + '&' + params.encode_url
      signing_key = consumer_secret.encode_url + '&' + token_secret.encode_url
      signature_base_str.hmac_sha1(signing_key).encode_base64.encode_url
    end,

    generate_oauth1_signature: lambda do |connection, input, path, verb|
      time = now
      nonce = time.to_f.to_s
      path = if path.include?('https://')
               path
             else
               "https://#{connection['base_url']}/api/#{path}"
             end
      url_params = input&.map do |key, value|
        "#{key}=#{value}"
      end || []
      auth_params = [
        "oauth_consumer_key=#{connection['consumer_key']}",
        "oauth_nonce=#{nonce}",
        'oauth_signature_method=HMAC-SHA1',
        "oauth_timestamp=#{time.to_i.to_s}",
        "oauth_token=#{connection['token_id']}",
        'oauth_version=1.0'
      ]
      params = call(:oauth1_params_norm, url_params, auth_params)

      auth = {
        method: verb.upcase,
        url: path,
        params: params,
        consumer_key: connection['consumer_key'],
        consumer_secret: connection['consumer_secret'],
        token_id: connection['token_id'],
        token_secret: connection['token_secret']
      }
      oauth_signature = call(:oauth1, auth)
      authorization = "OAuth " \
      "oauth_consumer_key=\"#{connection['consumer_key']}\"," \
      "oauth_token=\"#{connection['token_id']}\"," \
      'oauth_signature_method="HMAC-SHA1",' \
      "oauth_timestamp=\"#{time.to_i.to_s}\"," \
      "oauth_nonce=\"#{nonce}\"," \
      'oauth_version="1.0",' \
      "oauth_signature=\"#{oauth_signature}\""
    end,

    strip_params: lambda do |input|
      if input.is_a?(Array)
        input.map do |item|
          call('strip_params', item).presence
        end&.compact
      elsif input.is_a?(Hash)
        input.each_with_object({}) do |(key, value), hash|
          if value.is_a?(Array) || value.is_a?(Hash)
            hash[key] = call('strip_params', value).presence
          elsif value.present?
            hash[key] = value
          end
        end&.compact
      elsif input.present?
        input
      end
    end,

    # This method is for Custom action
    make_schema_builder_fields_sticky: lambda do |schema|
      schema.map do |field|
        if field['properties'].present?
          field['properties'] = call('make_schema_builder_fields_sticky',
                                     field['properties'])
        end
        field['sticky'] = true

        field
      end
    end,

    # Formats input/output schema to replace any special characters in name,
    # without changing other attributes (method required for custom action)
    format_schema: lambda do |input|
      input&.map do |field|
        if (props = field[:properties])
          field[:properties] = call('format_schema', props)
        elsif (props = field['properties'])
          field['properties'] = call('format_schema', props)
        end
        if (name = field[:name])
          field[:label] = field[:label].presence || name.labelize
          field[:name] = name.
                           gsub(/\W/) { |spl_chr| "__#{spl_chr.encode_hex}__" }
        elsif (name = field['name'])
          field['label'] = field['label'].presence || name.labelize
          field['name'] = name.
                            gsub(/\W/) { |spl_chr| "__#{spl_chr.encode_hex}__" }
        end

        field
      end
    end,

    # Formats payload to inject any special characters that previously removed
    format_payload: lambda do |payload|
      if payload.is_a?(Array)
        payload.map do |array_value|
          call('format_payload', array_value)
        end
      elsif payload.is_a?(Hash)
        payload.each_with_object({}) do |(key, value), hash|
          key = key.gsub(/__\w+__/) do |string|
            string.gsub(/__/, '').decode_hex.as_utf8
          end
          if value.is_a?(Array) || value.is_a?(Hash)
            value = call('format_payload', value)
          end
          hash[key] = value
        end
      end
    end,

    # Formats response to replace any special characters with valid strings
    # (method required for custom action)
    format_response: lambda do |response|
      response = response&.compact unless response.is_a?(String) || response
      if response.is_a?(Array)
        response.map do |array_value|
          call('format_response', array_value)
        end
      elsif response.is_a?(Hash)
        response.each_with_object({}) do |(key, value), hash|
          key = key.gsub(/\W/) { |spl_chr| "__#{spl_chr.encode_hex}__" }
          if value.is_a?(Array) || value.is_a?(Hash)
            value = call('format_response', value)
          end
          hash[key] = value
        end
      else
        response
      end
    end,

    get_url: lambda do |input|
      case input['object']
      when 'order_by_status'
        "orders/#{input.delete('status')}/detail"
      when 'order_status'
        "order/#{input.delete('id')}/#{input.delete('status')}"
      when 'pricesheet_by_template'
        'pricesheet'
      when 'product_by_ext_id'
        'product/external_id'
      when 'pricesheet_by_product_ext_id'
        'product/external_id'
      when 'buyer_by_company'
        "company/#{input.delete('id')}/buyer/#{input.delete('email')}"
      when 'buyer_company'
        "company/#{input.delete('id')}/add/buyer"
      when 'buyer_company_code'
        "company/code/#{input.delete('id')}/add/buyer"
      when 'buyer'
        "company/#{input.delete('id')}/update/buyer/#{input.delete('email')}"
      when 'pricesheet_product_ext_id'
        "pricesheet/#{input.delete('template')}/assign/product/" \
        "external_id/#{input.delete('id')}"
      else
        input['object']
      end
    end,

    get_metadata: lambda do |connection, object_name|
      url = "schemas/#{object_name}"
      authorization = call('generate_oauth1_signature',
                           connection, {}, url, 'GET' )
      get(url, {}).headers(Authorization: authorization).
        after_error_response(/.*/) do |_code, body, _header, message|
          error("#{message}: #{body}")
        end
    end,

    object_name_hash: lambda do |object|
      {
        'order_by_status' => 'order',
        'order_status' => 'order',
        'product_by_ext_id' => 'product',
        'pricesheet_by_template' => 'pricesheet',
        'buyer_company' => 'buyer',
        'buyer_company_code' => 'buyer',
        'pricesheet_product_ext_id' => 'pricesheet'
      }[object].presence || object
    end,

    address_schema: lambda do
      [
        { name: 'display_name' },
        { name: 'code' },
        { name: 'line_1' },
        { name: 'line_2' },
        { name: 'city' },
        { name: 'state', hint: 'E.g. GA' },
        { name: 'zip' },
        { name: 'country', hint: 'E.g. US' }
      ]
    end,

    order_schema: lambda do
      [
        { name: '_id' },
        { name: 'split', type: 'boolean' },
        { name: 'buyer_submitted', type: 'boolean' },
        { name: 'easy_order_viewed', type: 'boolean' },
        { name: 'easy_order_ready', type: 'boolean' },
        { name: 'collaborative_draft', type: 'boolean' },
        { name: 'ship_start', type: 'date',
          convert_input: 'format_date',
          hint: 'Provide Date format as <b>YYYY/mm/dd</b>' },
        { name: 'ship_end', type: 'date',
          convert_input: 'format_date',
          hint: 'Provide Date format as <b>YYYY/mm/dd</b>' },
        { name: 'edited', type: 'boolean' },
        { name: 'payment_status' },
        { name: 'is_drop_ship', type: 'boolean' },
        { name: '__shipment_status', type: 'array', of: 'string' },
        { name: '__lookups', type: 'array', of: 'string' },
        { name: '__brand_name' },
        { name: '__exported', type: 'boolean' },
        { name: '__uninitiated_order', type: 'boolean' },
        { name: '__includes_cancelled', type: 'boolean' },
        { name: '__cancelled_units', type: 'integer' },
        { name: '__cancelled_total', type: 'integer' },
        { name: '__is_rtp', label: 'Is RTP', type: 'boolean' },
        { name: 'creator_name' },
        { name: 'schema_id' },
        { name: 'line_items', type: 'array', of: 'object',
          properties: [
            { name: 'product', type: 'object',
              properties: [
                { name: '_id' },
                { name: 'style_number' },
                { name: 'color' },
                { name: 'color_code' },
                { name: 'brand_id' },
                { name: 'season' }
              ] },
            { name: 'ship_start', type: 'date_time' },
            { name: 'ship_end', type: 'date_time' },
            { name: 'sizes', type: 'array', of: 'object',
              properties: [
                { name: 'size' },
                { name: 'quantity', type: 'integer' },
                { name: 'price', type: 'number' },
                { name: 'original_price', type: 'integer' },
                { name: 'upc', label: 'UPC' }
              ] },
            { name: 'customization_split' },
            { name: 'warehouse' },
            { name: 'notes' },
            { name: 'discount', type: 'integer' },
            { name: 'prebook', type: 'boolean' },
            { name: '__customizations', type: 'array', of: 'object',
              properties: [
                { name: '_id' },
                { name: 'attribute_id' },
                { name: 'label' },
                { name: 'type' },
                { name: 'value' },
                { name: 'display_value' },
                { name: 'price', type: 'number' },
                { name: 'print_type' },
                { name: 'child_attributes', type: 'array', of: 'object',
                  properties: [
                    { name: '_id' },
                    { name: 'attribute_id' },
                    { name: 'label' },
                    { name: 'type' },
                    { name: 'value' },
                    { name: 'display_value' },
                    { name: 'child_attributes', type: 'array', of: 'string' }
                  ] }
              ] }
          ] },
        { name: 'status' },
        { name: 'currency_code' },
        { name: 'order_group_id' },
        { name: 'total', type: 'integer' },
        { name: 'selected_shipping_locations', type: 'array', of: 'string' },
        { name: '__split_overrides', type: 'array', of: 'object',
          properties: [
            { name: '_id' },
            { name: 'key' },
            { name: 'split_po' }
          ] },
        { name: '__configure_to_order_items', type: 'array', of: 'object',
          properties: [
            { name: '_id' },
            { name: 'configure_to_order_line_item', type: 'object',
              properties: [
                { name: 'line_item_id' },
                { name: 'transactional_trade_item' },
                { name: 'requested_quantity', type: 'integer' },
                { name: 'net_amount', type: 'integer' },
                { name: 'base_item_unit_price', type: 'integer' },
                { name: 'net_price', type: 'integer' },
                { name: 'configure_to_option', type: 'object',
                  properties: [
                    { name: 'option_value' },
                    { name: 'requested_option_quantity', type: 'integer' },
                    { name: 'option_unit_price', type: 'integer' },
                    { name: 'option_trade_item_identification' },
                    { name: 'label' },
                    { name: 'key' },
                    { name: 'type' }
                  ] }
              ] }
          ] },
        { name: 'shipments', type: 'array', of: 'object',
          properties: [
            { name: 'line_items', type: 'array', of: 'object',
              properties: [
                { name: 'brand_id' },
                { name: 'season' },
                { name: 'style_number' },
                { name: 'color' },
                { name: 'sizes' }
              ] },
            { name: 'type' },
            { name: 'tracking_numbers', type: 'array', of: 'string' },
            { name: 'status' },
            { name: 'shipment_date' }
          ] },
        { name: 'order_number' },
        { name: 'external_id' },
        { name: 'modified_on', type: 'date_time' },
        { name: 'edited_on', type: 'date_time' },
        { name: 'shipping_information', type: 'object',
          properties: [
            { name: 'service_type' },
            { name: 'service_code' },
            { name: 'carrier_code' },
            { name: 'carrier_friendly_name' },
            { name: 'price' },
            { name: 'final_amount' }
          ] },
        { name: 'retailer', type: 'object',
          properties: [
            { name: '_id' },
            { name: 'retailer_name' },
            { name: 'retailer_code' },
            { name: 'buyer_name' },
            { name: 'buyer_email' }
          ] },
        { name: 'order_type' },
        { name: 'notes' },
        { name: 'order_flow_type' },
        { name: 'billing_address', type: 'object',
          properties: [
            { name: 'display_name' },
            { name: 'line_1' },
            { name: 'country' },
            { name: 'line_2' },
            { name: 'city' },
            { name: 'state' },
            { name: 'zip' },
            { name: 'code' }
          ] },
        { name: 'shipping_address', type: 'object',
          properties: call('address_schema') },
        { name: 'submitted_by' },
        { name: 'customer_po_number', label: 'Customer PO number' },
        { name: 'discount', type: 'integer' },
        { name: 'additional_percentage', type: 'integer' },
        { name: 'locked', type: 'boolean' },
        { name: 'total_quantity', type: 'integer' },
        { name: 'style_number' },
        { name: 'existing_pdf_linesheet', label: 'Existing PDF linesheet' },
        { name: 'admin_pdf', label: 'Admin PDF' },
        { name: 'manager_pdf', label: 'Manager PDF' },
        { name: 'rep_pdf', label: 'Rep PDF' },
        { name: 'buyer_pdf', label: 'Buyer PDF' },
        { name: 'tech_pdf', label: 'Tech PDF' },
        { name: 'created_on', type: 'date_time' },
        { name: 'rep_name' },
        { name: 'rep_code' },
        { name: 'rep_email' },
        { name: 'start_ship', type: 'date_time' },
        { name: 'end_ship', type: 'date_time' }
      ]
    end,

    order_by_status_query_schema: lambda do
      [
        { name: 'status', optional: false,
          type: 'string', control_type: 'select',
          pick_list: [
            %w[Draft draft],
            %w[Review review],
            %w[Pending pending],
            %w[Approved approved],
            %w[Processed processed],
            %w[Shipped shipped],
            %w[Cancelled cancelled]
          ],
          toggle_hint: 'Select from list',
          toggle_field: {
            name: 'status',
            label: 'Status',
            type: :string,
            control_type: 'text',
            optional: false,
            toggle_hint: 'Use custom value',
            hint: 'Allowed values are draft, review, pending, ' \
            'approved, processed, shipped, cancelled.'
          } }
      ]
    end,

    order_create_schema: lambda do
      [
        { name: 'order_number', optional: false },
        { name: 'external_id', optional: false },
        { name: 'customer_po_number', label: 'Customer PO number' },
        { name: 'currency_code', optional: false,
          hint: 'E.g. USD' },
        { name: 'status' },
        { name: 'discount', type: 'number',
          render_input: 'float_conversion',
          hint: 'Provide Discount percentage (0 - 100)' },
        { name: 'ship_start', optional: false, type: 'date',
          convert_input: 'format_date',
          hint: 'Provide Date format as <b>YYYY/mm/dd</b>' },
        { name: 'ship_end', optional: false, type: 'date',
          convert_input: 'format_date',
          hint: 'Provide Date format as <b>YYYY/mm/dd</b>' },
        { name: 'rep_code' },
        { name: 'rep_email' },
        { name: 'notes' },
        { name: 'billing_address', type: 'object',
          properties: call('address_schema') },
        { name: 'shipping_address', type: 'object',
          properties: call('address_schema') },
        { name: 'retailer', type: 'object',
          properties: [
            { name: 'retailer_code', optional: false },
            { name: 'buyer_email', optional: false }
          ] },
        { name: 'line_items', optional: false,
          type: 'array', of: 'object',
          properties: [
            { name: 'product', type: 'object',
              properties: [
                { name: '_id' },
                { name: 'style_number' },
                { name: 'color' },
                { name: 'color_code' },
                { name: 'brand_id' },
                { name: 'season' }
              ] },
            { name: 'brand_id',
              hint: 'External ID of the product.' },
            { name: 'season' },
            { name: 'style_number' },
            { name: 'color' },
            { name: 'discount', type: 'number',
              render_input: 'float_conversion',
              hint: 'Provide Discount percentage (0 - 100)' },
            { name: 'ship_start', optional: false, type: 'date',
              convert_input: 'format_date',
              hint: 'Provide Date format as <b>YYYY/mm/dd</b>' },
            { name: 'ship_end', optional: false, type: 'date',
              convert_input: 'format_date',
              hint: 'Provide Date format as <b>YYYY/mm/dd</b>' },
            { name: 'notes' },
            { name: 'warehouse' },
            { name: 'sizes', type: 'array', of: 'object',
              properties: [
                { name: 'size', hint: 'E.g. Small' },
                { name: 'upc', label: 'UPC' },
                { name: 'quantity', type: 'number', optional: false,
                  render_input: 'float_conversion' },
                { name: 'price', type: 'number', optional: false,
                  render_input: 'float_conversion' },
                { name: 'original_price', type: 'number',
                  render_input: 'float_conversion' }
              ] },
            { name: 'prebook',
              type: 'boolean', control_type: 'checkbox',
              render_input: 'boolean_conversion',
              toggle_hint: 'Select from list',
              toggle_field: {
                name: 'prebook', label: 'Prebook',
                type: 'string', control_type: 'text',
                render_input: 'boolean_conversion',
                optional: true,
                toggle_hint: 'Use custom value',
                hint: 'Allowed values are true, false'
              } }
          ] },
        { name: 'shipping_information', type: 'object',
          properties: [
            { name: 'service_type' },
            { name: 'service_code' },
            { name: 'carrier_code' },
            { name: 'carrier_friendly_name' },
            { name: 'price', type: 'number',
              render_input: 'float_conversion' },
            { name: 'final_amount', type: 'number',
              render_input: 'float_conversion' }
          ] },
        { name: 'total', type: 'number',
          render_input: 'float_conversion' }
      ]
    end,

    pricesheet_schema: lambda do
      [
        { name: 'pricing', type: 'array', of: 'object',
          properties: [
            { name: 'wholesale', type: 'number',
              label: 'Wholesale price',
              render_input: 'float_conversion' },
            { name: 'retail', type: 'integer',
              label: 'Retailer price',
              render_input: 'integer_conversion' },
            { name: 'disabled',
              type: 'boolean', control_type: 'checkbox',
              render_input: 'boolean_conversion',
              toggle_hint: 'Select from list',
              toggle_field: {
                name: 'disabled', label: 'Disabled',
                type: 'string', control_type: 'text',
                render_input: 'boolean_conversion',
                optional: true,
                toggle_hint: 'Use custom value',
                hint: 'Allowed values are true, false'
              } },
            { name: 'sizes', type: 'array', of: 'object',
              properties: [
                { name: '_id', label: 'ID' },
                { name: 'wholesale', label: 'Wholesale size price' },
                { name: 'retail', label: 'Wholesale inventory price' },
                { name: 'size' }
              ] },
            { name: 'template', optional: false,
              label: 'Pricesheet template name' },
            { name: 'style_number' },
            { name: 'season' },
            { name: 'color' },
            { name: '_id' },
            { name: 'brand_id' },
            { name: 'product' },
            { name: 'currency_code' }
          ] }
      ]
    end,

    pricesheet_create_schema: lambda do
      [
        { name: 'template', optional: false,
          label: 'Pricesheet template name' }
      ].concat(call('pricesheet_schema'))
    end,

    pricesheet_by_product_ext_id_delete_schema: lambda do
      [
        { name: 'id', label: 'Product external_id or Brand_id', optional: false }
      ]
    end,

    pricesheet_by_product_ext_id_create_schema: lambda do
      call('pricesheet_schema')
    end,

    pricesheet_product_ext_id_add_schema: lambda do
      [
        { name: 'id', label: 'Product External ID or Brand ID', optional: false },
        { name: 'template', label: 'Pricesheet template name', optional: false }
      ].concat(call('pricesheet_schema'))
    end,

    rep_schema: lambda do
      [
        { name: 'name' },
        { name: 'email' },
        { name: 'ref', label: 'Sales Rep ID' },
        { name: '_id', label: 'Sales Ref internal ID' }
      ]
    end,

    company_schema: lambda do
      [
        { name: '_id' },
        { name: 'name', optional: false },
        { name: 'code', label: 'Company code' },
        { name: 'reps', type: 'array', of: 'object',
          properties: call('rep_schema') },
        { name: 'addresses', type: 'array', of: 'object',
          properties: [
            { name: 'display_name' },
            { name: 'line_1' },
            { name: 'line_2' },
            { name: 'city', hint: 'E.g. San Luis Obispo' },
            { name: 'state', hint: 'E.g. CA' },
            { name: 'zip' },
            { name: 'shipping_code' },
            { name: 'billing_code' },
            { name: 'type', label: 'Type',
              type: 'string', control_type: 'select',
              pick_list: [
                %w[Billing billing],
                %w[Shipping shipping],
                %w[Both both]
              ],
              toggle_hint: 'Select from list',
              toggle_field: {
                name: 'type',
                label: 'Type',
                type: :string,
                control_type: 'text',
                optional: true,
                toggle_hint: 'Use custom value',
                hint: 'Allowed values are billing, shipping or both.'
              } },
            { name: 'country', hint: 'E.g. United States' }
          ] },
        { name: 'allow_bulk',
          type: 'boolean', control_type: 'checkbox',
          render_input: 'boolean_conversion',
          toggle_hint: 'Select from list',
          toggle_field: {
            name: 'allow_bulk', label: 'Allow bulk',
            type: 'string', control_type: 'text',
            render_input: 'boolean_conversion',
            optional: true,
            toggle_hint: 'Use custom value',
            hint: 'Allowed values are true, false'
          } },
        { name: 'surcharge', type: 'number',
          render_input: 'float_conversion' },
        { name: 'discount', type: 'number',
          render_input: 'float_conversion' },
        { name: 'customer_groups', type: 'array', of: 'string' },
        { name: 'currency_code', optional: false },
        { name: 'active',
          type: 'boolean', control_type: 'checkbox',
          render_input: 'boolean_conversion',
          toggle_hint: 'Select from list',
          toggle_field: {
            name: 'active', label: 'Active',
            type: 'string', control_type: 'text',
            render_input: 'boolean_conversion',
            optional: true,
            toggle_hint: 'Use custom value',
            hint: 'Allowed values are true, false'
          } },
        { name: 'payment_terms' },
        { name: 'credit_status' },
        { name: 'warehouse' },
        { name: '__sortable_name' },
        { name: 'schema_id' },
        { name: 'buyers', type: 'array', of: 'object',
          properties: [
            { name: 'name' },
            { name: 'email' },
            { name: 'reps', type: 'array', of: 'object',
              label: 'Sales Rep info',
              properties: call('rep_schema') },
            { name: 'title' },
            { name: 'phone_office' },
            { name: 'phone_cell' },
            { name: '_id', label: 'Company user internal ID' },
            { name: 'ref', label: 'User ID' },
            { name: 'linesheets', type: 'array', of: 'string' },
            { name: 'last_viewed', type: 'date_time' }
          ] },
        { name: 'user_connections', type: 'array', of: 'object',
          properties: [
            { name: '_id' },
            { name: 'role_name' },
            { name: 'name' },
            { name: 'email' },
            { name: 'reps', type: 'array', of: 'object',
              properties: [
                { name: 'name' },
                { name: 'email' },
                { name: 'ref' },
                { name: '_id' }
              ] },
            { name: 'title' },
            { name: 'phone_office' },
            { name: 'phone_cell' },
            { name: 'ref' },
            { name: 'linesheets', type: 'array', of: 'string' },
            { name: 'last_viewed', type: 'date_time' }
          ] },
        { name: '__connected_brand_users', type: 'array', of: 'string' },
        { name: '__filter_key', type: 'array', of: 'string' },
        { name: '__search_key', type: 'array', of: 'string' },
        { name: 'created_on', type: 'date_time' },
        { name: 'default_discount', type: 'integer',
          render_input: 'integer_conversion' },
        { name: 'default_surcharge', type: 'integer',
          render_input: 'integer_conversion' },
        { name: 'pricing_template' },
        { name: 'currency_codes', type: 'array', of: 'string' },
        { name: 'modified_on', type: 'date_time' },
        { name: '__buyer_refs', type: 'array', of: 'string' }
      ]
    end,
  
    company_by_code_schema: lambda do
      call('company_schema')
    end,
  
    company_create_schema: lambda do
      call('company_schema').
        ignored('_id', '__sortable_name', 'schema_id', 'user_connections',
                '__connected_brand_users', '__filter_key', '__search_key',
                'created_on', 'default_discount', 'default_surcharge', 'modified_on', '__buyer_refs')
    end,
  
    company_by_code_create_schema: lambda do
      call('company_schema').
        ignored('_id', '__sortable_name', 'schema_id', 'user_connections',
                '__connected_brand_users', '__filter_key', '__search_key',
                'created_on', 'default_discount', 'default_surcharge', 'modified_on', '__buyer_refs')
    end,

    pricing_schema: lambda do
      [
        { name: 'USD', label: 'USD', type: 'object',
          properties: [
            { name: 'wholesale', type: 'number', optional: false,
              render_input: 'float_conversion' },
            { name: 'retail', type: 'number',
              render_input: 'float_conversion' },
            { name: 'disabled',
              type: 'boolean', control_type: 'checkbox',
              render_input: 'boolean_conversion',
              toggle_hint: 'Select from list',
              toggle_field: {
                name: 'disabled', label: 'Disabled',
                type: 'string', control_type: 'text',
                render_input: 'boolean_conversion',
                optional: true,
                toggle_hint: 'Use custom value',
                hint: 'Allowed values are true, false'
              } }
          ] }
      ]
    end,

    product_schema: lambda do
      [
        { name: '_id' },
        { name: 'active', type: 'boolean' },
        { name: 'archived', type: 'boolean' },
        { name: 'cancelled', type: 'boolean' },
        { name: 'images', type: 'array', of: 'string' },
        { name: 'available_now', type: 'boolean' },
        { name: 'size_groups', type: 'array', of: 'string' },
        { name: 'banners', type: 'array', of: 'string' },
        { name: '__original_composite_keys', type: 'boolean' },
        { name: '__tracks_inventory', type: 'boolean' },
        { name: '__inventory', type: 'array', of: 'string' },
        { name: '__warehouses', type: 'array', of: 'object',
          properties: [
            { name: 'id' },
            { name: 'brand_id' },
            { name: 'display_name' },
            { name: 'created_on', type: 'date_time' },
            { name: 'modified_on', type: 'date_time' },
            { name: 'code' },
            { name: 'sort', type: 'integer' },
            { name: 'active', type: 'boolean' }
          ] },
        { name: '__sold_out', type: 'boolean' },
        { name: '__merchandising_order', type: 'integer' },
        { name: '__pack_ids', label: 'Pack IDs', type: 'array', of: 'string' },
        { name: 'seasons', type: 'array', of: 'string' },
        { name: 'style_number' },
        { name: 'season' },
        { name: 'color' },
        { name: 'name' },
        { name: 'brand_id' },
        { name: 'sizes', type: 'array', of: 'object',
          properties: [
            { name: 'size' },
            { name: 'nrf_size_code', label: 'NRF size code' },
            { name: 'nrf_size_description', label: 'NRF size description' },
            { name: 'ean', label: 'EAN' }
          ] },
        { name: 'description' },
        { name: 'available_from', type: 'date_time' },
        { name: 'available_until', type: 'date_time' },
        { name: 'pricing', type: 'object',
          properties: [
            { name: 'USD', label: 'USD', type: 'object',
              properties: [
                { name: 'wholesale', type: 'integer' },
                { name: 'retail' }
              ] }
          ] },
        { name: '__pending_initial_pricing', type: 'boolean' },
        { name: '__brand_name' },
        { name: 'schema_id' },
        { name: '__size_ids', label: 'Size IDs', type: 'array', of: 'object',
          properties: [
            { name: '_id' },
            { name: 'size' }
          ] },
        { name: 'created_on', type: 'date_time' },
        { name: '__inventory_cache', type: 'array', of: 'object',
          properties: [
            { name: 'bucket', type: 'date',
              convert_input: 'format_date',
              hint: 'Provide Date format as <b>YYYY/mm/dd</b>' },
            { name: 'warehouse' },
            { name: 'sku_id', label: 'SKU ID' },
            { name: '_id' },
            { name: 'quantity', type: 'integer' }
          ] },
        { name: '__barcode' },
        { name: 'modified_on', type: 'date_time' },
        { name: '__size_run' },
        { name: '__size_range' },
        { name: 'unique_key' },
        { name: 'age' },
        { name: 'allocation' },
        { name: 'base_sku', label: 'Base SKU' },
        { name: 'ca_country_of_manufacture', label: 'CA country of manufacture' },
        { name: 'ca_country_of_sourcing', label: 'CA country of sourcing' },
        { name: 'ca_end_of_life', label: 'CA end of life' },
        { name: 'ca_hts_codes', label: 'CA HTS codes' },
        { name: 'ca_special_cost', label: 'CA special cost' },
        { name: 'ca_style_number', label: 'CA style number' },
        { name: 'ca_target_launch_date', label: 'CA target launch date' },
        { name: 'ca_vendor_currency', label: 'CA vendor currency' },
        { name: 'canada' },
        { name: 'cap_style' },
        { name: 'care_instructions' },
        { name: 'case_gtin', label: 'Case GTIN' },
        { name: 'case_height_in' },
        { name: 'case_length_in' },
        { name: 'case_pack_description' },
        { name: 'case_pack_indicator' },
        { name: 'case_volume_ft3' },
        { name: 'case_weight_lb' },
        { name: 'case_width_in' },
        { name: 'category' },
        { name: 'colg_only' },
        { name: 'collection_name' },
        { name: 'color_code' },
        { name: 'color_family' },
        { name: 'color_name' },
        { name: 'country_of_material_origin' },
        { name: 'country_of_origin' },
        { name: 'delivery_month' },
        { name: 'department' },
        { name: 'department_name' },
        { name: 'division' },
        { name: 'division_description' },
        { name: 'ds_indicator', label: 'DS indicator' },
        { name: 'emea', label: 'EMEA ' },
        { name: 'emea__cost_category_tariff_code',
          label: 'EMEA cost category tariff code' },
        { name: 'emea__finish', label: 'EMEA finish' },
        { name: 'emea__volume_l', label: 'EMEA volume l' },
        { name: 'emea__warranty', label: 'EMEA warranty' },
        { name: 'emea_end_of_life', label: 'EMEA end of life' },
        { name: 'emea_target_launch_date', label: 'EMEA target launch date' },
        { name: 'exclusive_retailers' },
        { name: 'fabric_description' },
        { name: 'garment_measurements' },
        { name: 'gender' },
        { name: 'gpc_brick_code', label: 'GPC brick code' },
        { name: 'hazmat_indicator' },
        { name: 'import_country' },
        { name: 'inner_pack_height_in' },
        { name: 'inner_pack_length_in' },
        { name: 'inner_pack_volume_ft3' },
        { name: 'inner_pack_weight_lb' },
        { name: 'inner_pack_width_in' },
        { name: 'ip_gtin', label: 'IP GTIN' },
        { name: 'item_status' },
        { name: 'item_sub_sub_type' },
        { name: 'item_sub_type' },
        { name: 'item_type' },
        { name: 'latam__apac', label: 'LATAM APAC' },
        { name: 'latam__apac_end_of_life', label: 'LATAM APAC end of life' },
        { name: 'latam__apac_target_launch_date',
          label: 'LATAM APAC target launch date' },
        { name: 'linesheet_name' },
        { name: 'natural_foods' },
        { name: 'notes_to_blm' },
        { name: 'nrf_color_code', label: 'NRF color code' },
        { name: 'nrf_color_description', label: 'NRF color description' },
        { name: 'odp_cross_reference_current_version' },
        { name: 'order_due_date' },
        { name: 'order_multiple' },
        { name: 'packaging' },
        { name: 'parent_style_id' },
        { name: 'primary_uom', label: 'Primary UOM' },
        { name: 'product_closures' },
        { name: 'product_size' },
        { name: 'product_weight' },
        { name: 'retail_packaging' },
        { name: 'retail_unit_height' },
        { name: 'retail_unit_length' },
        { name: 'retail_unit_volume' },
        { name: 'retail_unit_weight' },
        { name: 'retail_unit_width' },
        { name: 'size_fit_information' },
        { name: 'size_notes' },
        { name: 'special_cost' },
        { name: 'subcategory' },
        { name: 'unit_dims' },
        { name: 'unit_height' },
        { name: 'unit_length' },
        { name: 'unit_volume' },
        { name: 'unit_weight' },
        { name: 'unit_width' },
        { name: 'us', label: 'US' },
        { name: 'us_country_of_manufacture', label: 'US country of manufacture' },
        { name: 'us_country_of_sourcing', label: 'US country of sourcing' },
        { name: 'us_end_of_life', label: 'US end of life' },
        { name: 'us_hts_codes', label: 'US HTS codes' },
        { name: 'us_target_launch_date', label: 'US target launch date' },
        { name: 'us_vendor_currency', label: 'US vendor currency' },
        { name: 'volume_uom', label: 'Volume UOM' },
        { name: 'brand_name' },
        { name: 'cost_category_tariff_code' },
        { name: 'finish_series' },
        { name: 'latam_apac', label: 'LATAM_APAC' },
        { name: 'latam_apac_end_of_life', label: 'LATAM_APAC end of life' },
        { name: 'latam_apac_target_launch_date',
          label: 'LATAM_APAC target launch date' },
        { name: 'warranty_period' },
        { name: 'warehouses', type: 'array', of: 'object',
          properties: [
            { name: 'id' },
            { name: 'brand_id' },
            { name: 'display_name' },
            { name: 'created_on', type: 'date_time' },
            { name: 'modified_on', type: 'date_time' },
            { name: 'code' },
            { name: 'sort', type: 'integer' },
            { name: 'active', type: 'boolean' }
          ] },
        { name: '__cdn', label: 'CDN' },
        { name: 'order_closing' }
      ]
    end,

    product_create_schema: lambda do
      [
        { name: 'style_number', optional: false },
        { name: 'season', optional: false },
        { name: 'color', optional: false },
        { name: 'name', optional: false },
        { name: 'brand_id' },
        { name: 'unique_key' },
        { name: 'schema_id' },
        { name: 'sizes', type: 'array', of: 'object',
          properties: [
            { name: 'size' },
            { name: 'size_group' },
            {name: 'units_per_pack'},
            { name: 'pricing', type: 'object',
              properties: call('pricing_schema') }
          ] },
        { name: 'banners', type: 'array', of: 'string' },
        { name: 'size_groups', type: 'array', of: 'string' },
        { name: 'available_now',
          type: 'boolean', control_type: 'checkbox',
          render_input: 'boolean_conversion',
          toggle_hint: 'Select from list',
          toggle_field: {
            name: 'available_now', label: 'Available now',
            type: 'string', control_type: 'text',
            render_input: 'boolean_conversion',
            optional: true,
            toggle_hint: 'Use custom value',
            hint: 'Allowed values are true, false'
          } },
        { name: 'images', type: 'array', of: 'string' },
        { name: 'cancelled',
          type: 'boolean', control_type: 'checkbox',
          render_input: 'boolean_conversion',
          toggle_hint: 'Select from list',
          toggle_field: {
            name: 'cancelled', label: 'Cancelled',
            type: 'string', control_type: 'text',
            render_input: 'boolean_conversion',
            optional: true,
            toggle_hint: 'Use custom value',
            hint: 'Allowed values are true, false'
          } },
        { name: 'archived',
          type: 'boolean', control_type: 'checkbox',
          render_input: 'boolean_conversion',
          toggle_hint: 'Select from list',
          toggle_field: {
            name: 'archived', label: 'Archived',
            type: 'string', control_type: 'text',
            render_input: 'boolean_conversion',
            optional: true,
            toggle_hint: 'Use custom value',
            hint: 'Allowed values are true, false'
          } },
        { name: 'active',
          type: 'boolean', control_type: 'checkbox',
          render_input: 'boolean_conversion',
          toggle_hint: 'Select from list',
          toggle_field: {
            name: 'active', label: 'Active',
            type: 'string', control_type: 'text',
            render_input: 'boolean_conversion',
            optional: true,
            toggle_hint: 'Use custom value',
            hint: 'Allowed values are true, false'
          } },
        { name: 'description' },
        { name: 'available_from', type: 'date',
          convert_input: 'format_date' },
        { name: 'available_until', type: 'date',
          convert_input: 'format_date' },
        { name: 'order_closing', type: 'date_time' },
        { name: 'pricing', type: 'object',
          properties: call('pricing_schema') },
        { name: 'seasons', type: 'array', of: 'string' },
      ]
    end,

    buyer_schema: lambda do
      [
        { name: 'role_name', sticky: true },
        { name: 'name', sticky: true },
        { name: 'email', sticky: true },
        { name: 'reps', type: 'array', of: 'string',
          label: 'Sales Rep emails', sticky: true },
        { name: 'title', sticky: true },
        { name: 'phone_office', sticky: true },
        { name: 'phone_cell', sticky: true }
      ]
    end,

    buyer_company_add_schema: lambda do
      [{ name: 'id', optional: false, label: 'Company ID' }].
        concat(call('buyer_schema').ignored('role_name'))
    end,
    buyer_company_code_add_schema: lambda do
      [{ name: 'id', optional: false, label: 'Company code' }].
        concat(call('buyer_schema').ignored('role_name'))
    end,

    buyer_by_company_delete_schema: lambda do
      [
        { name: 'id', label: 'Company ID', optional: false },
        { name: 'email', label: 'Buyer email', optional: false }
      ]
    end,

    get_field_schema: lambda do |field, key_name, schema_type|
      if field.dig('details', 'allowed_values').present? && schema_type == 'input'
         [
           { name: key_name, label: field['name'],
             optional: !field['required'], custom: true,
             type: 'string', control_type: 'select',
             pick_list: field.dig('details', 'allowed_values').
                        map do |list|
                          [list['value'], list['value']]
                        end,
             toggle_hint: 'Select from list',
             toggle_field: {
               name: key_name,
               label: field['name'],
               type: :string,
               control_type: 'text',
               optional: !field['required'], custom: true,
               toggle_hint: 'Use custom value'
             } }
         ]
      else
        type = field['type'] == 'multi' ? { type: 'array', of: 'string' } : {}
        [{ name: key_name, label: field['name'], custom: true,
           optional: !field['required'] }.merge(type) ]
      end
    end,

    generate_custom_field_schema: lambda do |connection, object_name, schema, schema_type|
      if %w[order company product].include? object_name
        metadata = call('get_metadata', connection, object_name) || []

        metadata.dig(0, 'fields')&.each do |field|
          if field['key'].include?('.')
            nested_field = field['key'].split('.')
            nested_schema = schema.find { |val| val[:name] == nested_field[0] }

            next if nested_schema.blank? ||
              nested_schema[:properties].find { |val| val[:name] == nested_field[1] }

            field_schema = call('get_field_schema', field, nested_field[1], schema_type)
            nested_schema[:properties].concat(field_schema)
          else
            next if schema.find { |val| val[:name] == field['key'] }

            field_schema = call('get_field_schema', field, field['key'], schema_type)
            schema = schema.concat(field_schema)
          end
        end
      end
      schema
    end
  },

  object_definitions: {
    custom_action_input: {
      fields: lambda do |connection, config_fields|
        verb = config_fields['verb']
        input_schema = parse_json(config_fields.dig('input', 'schema') || '[]')
        data_props =
          input_schema.map do |field|
            if config_fields['request_type'] == 'multipart' &&
               field['binary_content'] == 'true'
              field['type'] = 'object'
              field['properties'] = [
                { name: 'file_content', optional: false },
                {
                  name: 'content_type',
                  default: 'text/plain',
                  sticky: true
                },
                { name: 'original_filename', sticky: true }
              ]
            end
            field
          end
        data_props = call('make_schema_builder_fields_sticky', data_props)
        input_data =
          if input_schema.present?
            if input_schema.dig(0, 'type') == 'array' &&
               input_schema.dig(0, 'details', 'fake_array')
              {
                name: 'data',
                type: 'array',
                of: 'object',
                properties: data_props.dig(0, 'properties')
              }
            else
              { name: 'data', type: 'object', properties: data_props }
            end
          end

        [
          {
            name: 'path',
            hint: 'Base URI is <b>' \
            "https://#{connection['base_url']}/api/" \
            '</b> - path will be appended to this URI. Use absolute URI to ' \
            'override this base URI.',
            optional: false
          },
          if %w[post put patch].include?(verb)
            {
              name: 'request_type',
              default: 'json',
              sticky: true,
              extends_schema: true,
              control_type: 'select',
              pick_list: [
                ['JSON request body', 'json'],
                ['URL encoded form', 'url_encoded_form'],
                ['Mutipart form', 'multipart'],
                ['Raw request body', 'raw']
              ]
            }
          end,
          {
            name: 'response_type',
            default: 'json',
            sticky: false,
            extends_schema: true,
            control_type: 'select',
            pick_list: [['JSON response', 'json'], ['Raw response', 'raw']]
          },
          if %w[get options delete].include?(verb)
            {
              name: 'input',
              label: 'Request URL parameters',
              sticky: true,
              add_field_label: 'Add URL parameter',
              control_type: 'form-schema-builder',
              type: 'object',
              properties: [
                {
                  name: 'schema',
                  sticky: input_schema.blank?,
                  extends_schema: true
                },
                input_data
              ].compact
            }
          else
            {
              name: 'input',
              label: 'Request body parameters',
              sticky: true,
              type: 'object',
              properties:
                if config_fields['request_type'] == 'raw'
                  [{
                    name: 'data',
                    sticky: true,
                    control_type: 'text-area',
                    type: 'string'
                  }]
                else
                  [
                    {
                      name: 'schema',
                      sticky: input_schema.blank?,
                      extends_schema: true,
                      schema_neutral: true,
                      control_type: 'schema-designer',
                      sample_data_type: 'json_input',
                      custom_properties:
                        if config_fields['request_type'] == 'multipart'
                          [{
                            name: 'binary_content',
                            label: 'File attachment',
                            default: false,
                            optional: true,
                            sticky: true,
                            render_input: 'boolean_conversion',
                            parse_output: 'boolean_conversion',
                            control_type: 'checkbox',
                            type: 'boolean'
                          }]
                        end
                    },
                    input_data
                  ].compact
                end
            }
          end,
          {
            name: 'request_headers',
            sticky: false,
            extends_schema: true,
            control_type: 'key_value',
            empty_list_title: 'Does this HTTP request require headers?',
            empty_list_text: 'Refer to the API documentation and add ' \
            'required headers to this HTTP request',
            item_label: 'Header',
            type: 'array',
            of: 'object',
            properties: [{ name: 'key' }, { name: 'value' }]
          },
          unless config_fields['response_type'] == 'raw'
            {
              name: 'output',
              label: 'Response body',
              sticky: true,
              extends_schema: true,
              schema_neutral: true,
              control_type: 'schema-designer',
              sample_data_type: 'json_input'
            }
          end,
          {
            name: 'response_headers',
            sticky: false,
            extends_schema: true,
            schema_neutral: true,
            control_type: 'schema-designer',
            sample_data_type: 'json_input'
          }
        ].compact
      end
    },
    custom_action_output: {
      fields: lambda do |_connection, config_fields|
        response_body = { name: 'body' }

        [
          if config_fields['response_type'] == 'raw'
            response_body
          elsif (output = config_fields['output'])
            output_schema = call('format_schema', parse_json(output))
            if output_schema.dig(0, 'type') == 'array' &&
               output_schema.dig(0, 'details', 'fake_array')
              response_body[:type] = 'array'
              response_body[:properties] = output_schema.dig(0, 'properties')
            else
              response_body[:type] = 'object'
              response_body[:properties] = output_schema
            end

            response_body
          end,
          if (headers = config_fields['response_headers'])
            header_props = parse_json(headers)&.map do |field|
              if field[:name].present?
                field[:name] = field[:name].gsub(/\W/, '_').downcase
              elsif field['name'].present?
                field['name'] = field['name'].gsub(/\W/, '_').downcase
              end
              field
            end

            { name: 'headers', type: 'object', properties: header_props }
          end
        ].compact
      end
    },

    search_object_input: {
      fields: lambda do |_connection, config_fields|
        next [] if config_fields.blank?

        call("#{config_fields['object']}_query_schema")
      end
    },

    search_object_output: {
      fields: lambda do |connection, config_fields|
        next [] if config_fields.blank?

        object_name = call('object_name_hash', config_fields['object'])
        schema = call("#{object_name}_schema")

        [
          { name: 'records', label: object_name.pluralize.labelize,
            type: 'array', of: 'object',
            properties: call('generate_custom_field_schema', connection,
                             object_name, schema, 'output') }
        ]
      end
    },

    get_object_input: {
      fields: lambda do |_connection, config_fields|
        next [] if config_fields.blank?

        label = {
          'product_by_ext_id' => 'Product brand ID',
          'pricesheet_by_template' => 'Pricesheet template name'
        }[config_fields['object']].presence

        [
          { name: 'id', optional: false,
            label: label || "#{config_fields['object']&.labelize} ID" }
        ]
      end
    },

    get_object_output: {
      fields: lambda do |connection, config_fields|
        next [] if config_fields.blank?

        object_name = call('object_name_hash', config_fields['object'])
        schema = call("#{object_name}_schema")
        call('generate_custom_field_schema', connection, object_name, schema, 'output')
      end
    },

    create_object_input: {
      fields: lambda do |connection, config_fields|
        next [] if config_fields.blank?

        object_name = call('object_name_hash', config_fields['object'])
        schema = call("#{object_name}_create_schema")

        call('generate_custom_field_schema', connection, object_name, schema, 'input')
      end
    },

    create_object_output: {
      fields: lambda do |connection, config_fields|
        next [] if config_fields.blank?

        if config_fields['object'] == 'pricesheet'
          [
            { name: 'updates', type: 'array', of: 'string' },
            { name: 'errors', type: 'array', of: 'string' }
          ]
        else
          object_name = call('object_name_hash', config_fields['object'])
          schema = call("#{object_name}_schema")
          call('generate_custom_field_schema', connection, object_name, schema, 'output')
        end
      end
    },

    update_object_input: {
      fields: lambda do |connection, config_fields|
        next [] if config_fields.blank?

        label = {
          'product_by_ext_id' => 'Product external or brand ID',
          'pricesheet_by_product_ext_id' => 'Product external ID or brand ID'
        }[config_fields['object']].presence

        schema = if config_fields['object'] == 'order_status'
                   [{ name: 'id', optional: false, label: 'Order ID' }].
                     concat(call('order_by_status_query_schema'))
                 elsif config_fields['object'] == 'buyer'
                     call('buyer_by_company_delete_schema').
                      concat(call('buyer_schema').ignored('email'))
                 else
                   object_name = call('object_name_hash', config_fields['object'])
                   [
                     { name: 'id', optional: false,
                       label: label || "#{config_fields['object']&.labelize} ID" }
                   ].concat(call("#{object_name}_create_schema"))
                 end
        call('generate_custom_field_schema', connection, object_name, schema, 'input')
      end
    },

    update_object_output: {
      fields: lambda do |connection, config_fields|
        next [] if config_fields.blank?

        if config_fields['object'] == 'pricesheet_by_product_ext_id'
          [
            { name: 'records', label: 'Pricesheets',
              type: 'array', of: 'object',
              properties: [
                { name: 'message' },
                { name: 'index', type: 'integer' },
                { name: 'success' }
              ] }
          ]
        else
          object_name = call('object_name_hash', config_fields['object'])
          schema = call("#{object_name}_schema")
          call('generate_custom_field_schema', connection, object_name, schema, 'output')
        end
      end
    },

    delete_object_input: {
      fields: lambda do |_connection, config_fields|
        next [] if config_fields.blank?

        call("#{config_fields['object']}_delete_schema")
      end
    },

    delete_object_output: {
      fields: lambda do |_connection, config_fields|
        next [] if config_fields.blank? || config_fields['object'] == 'buyer_by_company'

        [{ name: 'success', type: 'boolean' }]
      end
    },

    add_record_object_input: {
      fields: lambda do |_connection, config_fields|
        next [] if config_fields.blank?

        call("#{config_fields['object']}_add_schema")
      end
    },

    add_record_object_output: {
      fields: lambda do |_connection, config_fields|
        next [] if config_fields.blank?

        if config_fields['object'] == 'pricesheet_product_ext_id'
          [
            { name: 'updates', type: 'array', of: 'string' },
            { name: 'errors', type: 'array', of: 'string' }
          ]
        else
          object_name = call('object_name_hash', config_fields['object'])
          call("#{object_name}_schema")
        end
      end
    }
  },

  actions: {
    custom_action: {
      subtitle: 'Build your own NuORDER action with a HTTP request',

      description: lambda do |object_value, _object_label|
        "<span class='provider'>" \
        "#{object_value[:action_name] || 'Custom action'}</span> in " \
        "<span class='provider'>NuORDER</span>"
      end,

      help: {
        body: 'Build your own NuORDER action with a HTTP request. ' \
        'The request will be authorized with your NuORDER connection.',
        learn_more_url: 'https://nuorderapi1.docs.apiary.io/',
        learn_more_text: 'NuORDER API documentation'
      },

      config_fields: [
        {
          name: 'action_name',
          hint: "Give this action you're building a descriptive name, e.g. " \
          'create record, get record',
          default: 'Custom action',
          optional: false,
          schema_neutral: true
        },
        {
          name: 'verb',
          label: 'Method',
          hint: 'Select HTTP method of the request',
          optional: false,
          control_type: 'select',
          pick_list: %w[get post put patch delete].
                       map { |verb| [verb.upcase, verb] }
        }
      ],

      input_fields: lambda do |object_definition|
        object_definition['custom_action_input']
      end,

      execute: lambda do |connection, input|
        verb = input['verb']
        if %w[get post put patch options delete].exclude?(verb)
          error("#{verb.upcase} not supported")
        end
        path = input['path']
        param_object = %w[post put patch].include?(verb) ? 'input_param' : 'input'
        authorization = call('generate_oauth1_signature', connection,
                             input.dig(param_object, 'data'), path, verb)

        data = input.dig('input', 'data') || {}
        if input['request_type'] == 'multipart'
          data = data.each_with_object({}) do |(key, val), hash|
            hash[key] = if val.is_a?(Hash)
                          [val[:file_content],
                           val[:content_type],
                           val[:original_filename]]
                        else
                          val
                        end
          end
        end
        request_headers = input['request_headers']
          &.each_with_object({}) do |item, hash|
          hash[item['key']] = item['value']
        end || {}
        request = case verb
                  when 'get'
                    get(path, data)
                  when 'post'
                    if input['request_type'] == 'raw'
                      post(path).request_body(data)
                    else
                      post(path, data)
                    end
                  when 'put'
                    if input['request_type'] == 'raw'
                      put(path).request_body(data)
                    else
                      put(path, data)
                    end
                  when 'patch'
                    if input['request_type'] == 'raw'
                      patch(path).request_body(data)
                    else
                      patch(path, data)
                    end
                  when 'options'
                    options(path, data)
                  when 'delete'
                    delete(path, data)
                  end.case_sensitive_headers(
                    request_headers.merge(Authorization: authorization)
                  )
        request = case input['request_type']
                  when 'url_encoded_form'
                    request.request_format_www_form_urlencoded
                  when 'multipart'
                    request.request_format_multipart_form
                  else
                    request
                  end
        response =
          if input['response_type'] == 'raw'
            request.response_format_raw
          else
            request
          end.
            after_error_response(/.*/) do |code, body, headers, message|
            error({ code: code, message: message, body: body, headers: headers }.
              to_json)
          end

        response.after_response do |_code, res_body, res_headers|
          {
            body: res_body ? call('format_response', res_body) : nil,
            headers: res_headers
          }
        end
      end,

      output_fields: lambda do |object_definition|
        object_definition['custom_action_output']
      end
    },

    search_records: {
      title: 'Search records',
      subtitle: 'Search records, e.g. orders, in NuORDER',
      description: lambda do |_input, search_object_list|
        "Search <span class='provider'>" \
        "#{search_object_list[:object]&.pluralize || 'records'}</span> " \
        'in <span class="provider">NuORDER</span>'
      end,

      help: 'Returns all records that matches your search criteria.',

      config_fields: [
        {
          name: 'object',
          optional: false,
          control_type: 'select',
          pick_list: :search_object_list,
          hint: 'Select the object from list.'
        }
      ],

      input_fields: lambda do |object_definitions|
        object_definitions['search_object_input']
      end,

      execute: lambda do |connection, input|
        url = call('get_url', input)
        payload = input.except('object')
        authorization = call('generate_oauth1_signature',
                             connection, payload, url, 'GET' )
        response = get(url, payload).headers(Authorization: authorization).
                   after_error_response(/.*/) do |_code, body, _header, message|
                     error("#{message}: #{body}")
                   end

        { records: response }
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['search_object_output']
      end
    },

    get_record: {
      title: 'Get record details',
      subtitle: 'Retrieve the details of record, e.g. order in NuORDER',
      description: lambda do |_input, get_object_list|
        "Get <span class='provider'>" \
        "#{get_object_list[:object] || 'record'}</span> " \
        'in <span class="provider">NuORDER</span>'
      end,

      help: 'Retrieve the details of record, e.g. order.',

      config_fields: [
        {
          name: 'object',
          optional: false,
          control_type: 'select',
          pick_list: :get_object_list,
          hint: 'Select the object from list.'
        }
      ],

      input_fields: lambda do |object_definitions|
        object_definitions['get_object_input']
      end,

      execute: lambda do |connection, input|
        url = "#{call('get_url', input)}/#{input['id']}"
        payload = input.except('object', 'id')
        authorization = call('generate_oauth1_signature',
                             connection, payload, url, 'GET' )
        get(url, payload).headers(Authorization: authorization).
          after_error_response(/.*/) do |_code, body, _header, message|
            error("#{message}: #{body}")
          end
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['get_object_output']
      end
    },

    create_record: {
      title: 'Create record',
      subtitle: 'Create record, e.g. order, in NuORDER',
      description: lambda do |_input, create_object_list|
        "Create <span class='provider'>" \
        "#{create_object_list[:object] || 'record'}</span> " \
        'in <span class="provider">NuORDER</span>'
      end,

      help: 'Create a record, e.g. order, in NuORDER.',

      config_fields: [
        {
          name: 'object',
          optional: false,
          control_type: 'select',
          pick_list: :create_object_list,
          hint: 'Select the object from list.'
        }
      ],

      input_fields: lambda do |object_definitions|
        object_definitions['create_object_input']
      end,

      execute: lambda do |connection, input|
        path = input['object'] == 'pricesheet' ? input.delete('template') : 'new'
        url = "#{call('get_url', input)}/#{path}"
        input['pricing'] = call('strip_params', input['pricing']).presence || {}
        payload = input.except('object')
        authorization = call('generate_oauth1_signature',
                             connection, {}, url, 'PUT' )

        put(url, payload).headers(Authorization: authorization).
          after_error_response(/.*/) do |_code, body, _header, message|
            error("#{message}: #{body}")
          end
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['create_object_output']
      end
    },

    update_record: {
      title: 'Update record',
      subtitle: 'Update record, e.g. order, in NuORDER',
      description: lambda do |_input, update_object_list|
        "Update <span class='provider'>" \
        "#{update_object_list[:object] || 'record'}</span> " \
        'in <span class="provider">NuORDER</span>'
      end,

      help: 'Update a record, e.g. order, in NuORDER.',

      config_fields: [
        {
          name: 'object',
          optional: false,
          control_type: 'select',
          pick_list: :update_object_list,
          hint: 'Select the object from list.'
        }
      ],

      input_fields: lambda do |object_definitions|
        object_definitions['update_object_input']
      end,

      execute: lambda do |connection, input|
        if input['object'] == 'pricesheet_by_product_ext_id'
          path = "#{input.delete('id')}/pricesheets"
          payload = input['pricing']
        else
          path = input.delete('id') unless %w[buyer order_status].include? input['object']
          input['pricing'] = call('strip_params', input['pricing']).presence || {}
          payload = input.except('object')
        end

        url = "#{call('get_url', input)}/#{path}"
        authorization = call('generate_oauth1_signature',
                              connection, {}, url, 'POST' )

        response = post(url, payload).headers(Authorization: authorization).
                   after_error_response(/.*/) do |_code, body, _header, message|
                     error("#{message}: #{body}")
                   end
        if input['object'] == 'pricesheet_by_product_ext_id'
          { records: response }
        else
          response
        end
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['update_object_output']
      end
    },

    delete_record: {
      title: 'Delete record',
      subtitle: 'Detete record, e.g. buyer, in NuORDER',
      description: lambda do |_input, delete_object_list|
        "Delete <span class='provider'>" \
        "#{delete_object_list[:object] || 'record'}</span> " \
        'in <span class="provider">NuORDER</span>'
      end,

      help: 'Delete a record, e.g. buyer, in NuORDER.',

      config_fields: [
        {
          name: 'object',
          optional: false,
          control_type: 'select',
          pick_list: :delete_object_list,
          hint: 'Select the object from list.'
        }
      ],

      input_fields: lambda do |object_definitions|
        object_definitions['delete_object_input']
      end,

      execute: lambda do |connection, input|
        url = call('get_url', input)
        if input['object'] == 'pricesheet_by_product_ext_id'
          url = url + "/#{input.delete('id')}/pricesheets"
        end
        payload = input.except('object', 'id')
        authorization = call('generate_oauth1_signature',
                             connection, payload, url, 'DELETE' )

        delete(url).params(payload).headers(Authorization: authorization).
          after_error_response(/.*/) do |_code, body, _header, message|
            error("#{message}: #{body}")
          end
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['delete_object_output']
      end
    },

    add_record_to_object: {
      title: 'Add record to object',
      subtitle: 'Add record to object, e.g. buyer to company, in NuORDER',
      description: lambda do |_input, add_record_object_list|
        "Add <span class='provider'>" \
        "#{add_record_object_list[:object] || 'record to object'}</span> " \
        'in <span class="provider">NuORDER</span>'
      end,

      help: 'Add record to object, e.g. buyer to company, in NuORDER.',

      config_fields: [
        {
          name: 'object',
          optional: false,
          control_type: 'select',
          pick_list: :add_record_object_list,
          hint: 'Select the object from list.'
        }
      ],

      input_fields: lambda do |object_definitions|
        object_definitions['add_record_object_input']
      end,

      execute: lambda do |connection, input|
        url = call('get_url', input)
        payload = input.except('object')
        request = if %w[buyer_company buyer_company_code].include?(input['object'])
                    authorization = call('generate_oauth1_signature',
                                          connection, {}, url, 'PUT' )
                    put(url, payload)
                  else
                    authorization = call('generate_oauth1_signature',
                                          connection, {}, url, 'POST' )
                    post(url, payload)
                  end
        request.headers(Authorization: authorization).
          after_error_response(/.*/) do |_code, body, _header, message|
            error("#{message}: #{body}")
          end
      end,

      output_fields: lambda do |object_definitions|
        object_definitions['add_record_object_output']
      end
    },

    remove_record_to_object: {
      title: 'Remove/delete record from object',
      subtitle: 'Remove/delete record from object, e.g. buyer from company, in NuORDER',
      description: lambda do |_input, remove_record_object_list|
        "Remove/delete <span class='provider'>" \
        "#{remove_record_object_list[:object] || 'record from object'}</span> " \
        'in <span class="provider">NuORDER</span>'
      end,

      help: 'Remove/delete record from object, e.g. buyer from company, in NuORDER.',

      config_fields: [
        {
          name: 'object',
          optional: false,
          control_type: 'select',
          pick_list: :remove_record_object_list,
          hint: 'Select the object from list.'
        }
      ],

      input_fields: lambda do |object_definitions|
        object_definitions['add_record_object_input'].
          only('template', 'id')
      end,

      execute: lambda do |connection, input|
        url = if input['object'] == 'pricesheet_product_ext_id'
                "pricesheet/#{input.delete('template')}/remove/product/" \
                "external_id/#{input.delete('id')}"
              else
                call('get_url', input)
              end
        authorization = call('generate_oauth1_signature',
                             connection, {}, url, 'DELETE' )
        delete(url).params({}).headers(Authorization: authorization).
          after_error_response(/.*/) do |_code, body, _header, message|
            error("#{message}: #{body}")
          end
      end,

      output_fields: lambda do |object_definitions|
        [{ name: 'success', type: 'boolean' }]
      end,
    }
  },

  pick_lists: {
    search_object_list: lambda do |_connection|
      [
        %w[Order\ by\ status order_by_status]
      ]
    end,

    get_object_list: lambda do |_connection|
      [
        %w[Order order],
        %w[Company company],
        %w[Product product],
        %w[Product\ by\ external\ ID product_by_ext_id],
        %w[Pricesheet\ by\ template pricesheet_by_template]
      ]
    end,

    create_object_list: lambda do |_connection|
      [
        %w[Order order],
        %w[Company company],
        %w[Product product],
        %w[Pricesheet pricesheet]
      ]
    end,

    update_object_list: lambda do |_connection|
      [
        %w[Order order],
        %w[Order\ status order_status],
        %w[Company company],
        %w[Product product],
        %w[Product\ by\ external\ ID product_by_ext_id],
        %w[Pricesheet\ by\ product\ external\ ID pricesheet_by_product_ext_id],
        %w[Buyer buyer]
      ]
    end,

    delete_object_list: lambda do |_connection|
      [
        %w[Pricesheet\ by\ product\ external\ ID pricesheet_by_product_ext_id],
        %w[Buyer\ by\ company\ ID buyer_by_company]
      ]
    end,

    add_record_object_list: lambda do |_connection|
      [
        %w[Pricesheet\ to\ product\ by\ external\ ID pricesheet_product_ext_id],
        %w[Buyer\ to\ company buyer_company],
        %w[Buyer\ to\ company\ by\ code buyer_company_code]
      ]
    end,

    remove_record_object_list: lambda do |_connection|
      [
        %w[Pricesheet\ from\ product\ by\ external\ ID pricesheet_product_ext_id]
      ]
    end
  }
}
